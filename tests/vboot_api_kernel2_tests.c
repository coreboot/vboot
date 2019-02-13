/* Copyright (c) 2013 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Tests for vboot_api_kernel, part 2
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "2sysincludes.h"
#include "2api.h"
#include "2misc.h"
#include "2nvstorage.h"
#include "gbb_header.h"
#include "host_common.h"
#include "load_kernel_fw.h"
#include "rollback_index.h"
#include "test_common.h"
#include "vboot_audio.h"
#include "vboot_common.h"
#include "vboot_display.h"
#include "vboot_kernel.h"
#include "vboot_struct.h"

/* Mock data */
static uint8_t shared_data[VB_SHARED_DATA_MIN_SIZE];
static VbSharedDataHeader *shared = (VbSharedDataHeader *)shared_data;
static LoadKernelParams lkp;
static uint8_t workbuf[VB2_KERNEL_WORKBUF_RECOMMENDED_SIZE];
static struct vb2_context ctx;
static struct vb2_shared_data *sd;

static int shutdown_request_calls_left;
static int shutdown_request_power_held;
static int shutdown_via_lid_close;
static int audio_looping_calls_left;
static uint32_t vbtlk_retval;
static int vbexlegacy_called;
static enum VbAltFwIndex_t altfw_num;
static uint64_t current_ticks;
static int trust_ec;
static int virtdev_set;
static uint32_t virtdev_retval;
static uint32_t mock_keypress[16];
static uint32_t mock_keyflags[8];
static uint32_t mock_keypress_count;
static uint32_t mock_switches[8];
static uint32_t mock_switches_count;
static int mock_switches_are_stuck;
static uint32_t screens_displayed[8];
static uint32_t screens_count = 0;
static uint32_t mock_num_disks[8];
static uint32_t mock_num_disks_count;
static int tpm_set_mode_called;
static enum vb2_tpm_mode tpm_mode;

static char set_vendor_data[32];
static int set_vendor_data_called;

extern enum VbEcBootMode_t VbGetMode(void);
extern struct RollbackSpaceFwmp *VbApiKernelGetFwmp(void);

/* Reset mock data (for use before each test) */
static void ResetMocks(void)
{
	memset(VbApiKernelGetFwmp(), 0, sizeof(struct RollbackSpaceFwmp));

	memset(&shared_data, 0, sizeof(shared_data));
	VbSharedDataInit(shared, sizeof(shared_data));

	memset(&lkp, 0, sizeof(lkp));

	memset(&ctx, 0, sizeof(ctx));
	ctx.workbuf = workbuf;
	ctx.workbuf_size = sizeof(workbuf);
	vb2_init_context(&ctx);
	vb2_nv_init(&ctx);

	sd = vb2_get_sd(&ctx);
	sd->vbsd = shared;

	shutdown_request_calls_left = -1;
	shutdown_request_power_held = -1;
	shutdown_via_lid_close = 0;
	audio_looping_calls_left = 30;
	vbtlk_retval = 1000;
	vbexlegacy_called = 0;
	altfw_num = -100;
	current_ticks = 0;
	trust_ec = 0;
	virtdev_set = 0;
	virtdev_retval = 0;
	set_vendor_data_called = 0;

	memset(screens_displayed, 0, sizeof(screens_displayed));
	screens_count = 0;

	memset(mock_keypress, 0, sizeof(mock_keypress));
	memset(mock_keyflags, 0, sizeof(mock_keyflags));
	mock_keypress_count = 0;

	memset(mock_switches, 0, sizeof(mock_switches));
	mock_switches_count = 0;
	mock_switches_are_stuck = 0;

	memset(mock_num_disks, 0, sizeof(mock_num_disks));
	mock_num_disks_count = 0;

	tpm_set_mode_called = 0;
	tpm_mode = VB2_TPM_MODE_ENABLED_TENTATIVE;
}

/* Mock functions */

uint32_t VbExIsShutdownRequested(void)
{
	if (shutdown_request_calls_left == 0)
		return shutdown_via_lid_close ?
			VB_SHUTDOWN_REQUEST_LID_CLOSED :
			VB_SHUTDOWN_REQUEST_POWER_BUTTON;
	else if (shutdown_request_calls_left > 0)
		shutdown_request_calls_left--;

	if (shutdown_request_power_held >= 0) {
		/* Hold power button for 10 calls, then release for 10. */
		if (shutdown_request_calls_left % 10 == 0)
			shutdown_request_power_held
				= !shutdown_request_power_held;
		if (shutdown_request_power_held)
			return VB_SHUTDOWN_REQUEST_POWER_BUTTON;
	}

	return 0;
}

uint32_t VbExKeyboardRead(void)
{
	return VbExKeyboardReadWithFlags(NULL);
}

uint32_t VbExKeyboardReadWithFlags(uint32_t *key_flags)
{
	if (mock_keypress_count < ARRAY_SIZE(mock_keypress)) {
		if (key_flags != NULL)
			*key_flags = mock_keyflags[mock_keypress_count];
		return mock_keypress[mock_keypress_count++];
	} else
		return 0;
}

uint32_t VbExGetSwitches(uint32_t request_mask)
{
	if (mock_switches_are_stuck)
		return mock_switches[0] & request_mask;
	if (mock_switches_count < ARRAY_SIZE(mock_switches))
		return mock_switches[mock_switches_count++] & request_mask;
	else
		return 0;
}

int VbExLegacy(enum VbAltFwIndex_t _altfw_num)
{
	vbexlegacy_called++;
	altfw_num = _altfw_num;

	/* VbExLegacy() can only return failure, or not return at all. */
	return VBERROR_UNKNOWN;
}

void VbExSleepMs(uint32_t msec)
{
	current_ticks += (uint64_t)msec * VB_USEC_PER_MSEC;
}

uint64_t VbExGetTimer(void)
{
	return current_ticks;
}

VbError_t VbExDiskGetInfo(VbDiskInfo **infos_ptr, uint32_t *count,
			  uint32_t disk_flags)
{
	if (mock_num_disks_count < ARRAY_SIZE(mock_num_disks)) {
		if (mock_num_disks[mock_num_disks_count] == -1)
			return VBERROR_SIMULATED;
		else
			*count = mock_num_disks[mock_num_disks_count++];
	} else {
		*count = 0;
	}
	return VBERROR_SUCCESS;
}

VbError_t VbExDiskFreeInfo(VbDiskInfo *infos,
			   VbExDiskHandle_t preserve_handle)
{
	return VBERROR_SUCCESS;
}

int VbExTrustEC(int devidx)
{
	return trust_ec;
}

int vb2_audio_looping(void)
{
	if (audio_looping_calls_left == 0)
		return 0;
	else if (audio_looping_calls_left > 0)
		audio_looping_calls_left--;

	return 1;
}

uint32_t VbTryLoadKernel(struct vb2_context *ctx, uint32_t get_info_flags)
{
	return vbtlk_retval + get_info_flags;
}

VbError_t VbDisplayScreen(struct vb2_context *ctx, uint32_t screen, int force,
			  const VbScreenData *data)
{
	if (screens_count < ARRAY_SIZE(screens_displayed))
		screens_displayed[screens_count++] = screen;

	return VBERROR_SUCCESS;
}

uint32_t SetVirtualDevMode(int val)
{
	virtdev_set = val;
	return virtdev_retval;
}

VbError_t VbExSetVendorData(const char *vendor_data_value)
{
	set_vendor_data_called = 1;
	strncpy(set_vendor_data, vendor_data_value, sizeof(set_vendor_data));

	return VBERROR_SUCCESS;
}

int vb2ex_tpm_set_mode(enum vb2_tpm_mode mode_val)
{
	tpm_set_mode_called = 1;
	/*
	 * This mock will pretend that any call will fail if the tpm is
	 * already disabled (e.g., as if the code always tries to contact the
	 * tpm to issue a command).  The real version may eventually be changed
	 * to return success if the incoming request is also to disable, but
	 * the point here is to have a way to simulate failure.
	 */
	if (tpm_mode == VB2_TPM_MODE_DISABLED) {
		return VB2_ERROR_UNKNOWN;
	}
	tpm_mode = mode_val;
	return VB2_SUCCESS;
}

/* Tests */

static void VbUserConfirmsTest(void)
{
	printf("Testing VbUserConfirms()...\n");

	ResetMocks();
	shutdown_request_calls_left = 1;
	TEST_EQ(VbUserConfirms(&ctx, 0), -1, "Shutdown requested");

	ResetMocks();
	mock_keypress[0] = VB_BUTTON_POWER_SHORT_PRESS;
	TEST_EQ(VbUserConfirms(&ctx, 0), -1, "Shutdown requested");

	ResetMocks();
	mock_keypress[0] = VB_KEY_ENTER;
	TEST_EQ(VbUserConfirms(&ctx, 0), 1, "Enter");

	ResetMocks();
	mock_keypress[0] = VB_KEY_ESC;
	TEST_EQ(VbUserConfirms(&ctx, 0), 0, "Esc");

	ResetMocks();
	mock_keypress[0] = ' ';
	shutdown_request_calls_left = 1;
	TEST_EQ(VbUserConfirms(&ctx, VB_CONFIRM_SPACE_MEANS_NO), 0,
		"Space means no");

	ResetMocks();
	mock_keypress[0] = ' ';
	shutdown_request_calls_left = 1;
	TEST_EQ(VbUserConfirms(&ctx, 0), -1, "Space ignored");

	ResetMocks();
	mock_keypress[0] = VB_KEY_ENTER;
	mock_keyflags[0] = VB_KEY_FLAG_TRUSTED_KEYBOARD;
	TEST_EQ(VbUserConfirms(&ctx, VB_CONFIRM_MUST_TRUST_KEYBOARD),
		1, "Enter with trusted keyboard");

	ResetMocks();
	mock_keypress[0] = VB_KEY_ENTER;	/* untrusted */
	mock_keypress[1] = ' ';
	TEST_EQ(VbUserConfirms(&ctx,
			       VB_CONFIRM_SPACE_MEANS_NO |
			       VB_CONFIRM_MUST_TRUST_KEYBOARD),
		0, "Untrusted keyboard");

	ResetMocks();
	mock_switches[0] = VB_SWITCH_FLAG_REC_BUTTON_PRESSED;
	TEST_EQ(VbUserConfirms(&ctx,
			       VB_CONFIRM_SPACE_MEANS_NO |
			       VB_CONFIRM_MUST_TRUST_KEYBOARD),
		1, "Recovery button");

	ResetMocks();
	mock_keypress[0] = VB_KEY_ENTER;
	mock_keypress[1] = 'y';
	mock_keypress[2] = 'z';
	mock_keypress[3] = ' ';
	mock_switches[0] = VB_SWITCH_FLAG_REC_BUTTON_PRESSED;
	mock_switches_are_stuck = 1;
	TEST_EQ(VbUserConfirms(&ctx,
			       VB_CONFIRM_SPACE_MEANS_NO |
			       VB_CONFIRM_MUST_TRUST_KEYBOARD),
		0, "Recovery button stuck");

	printf("...done.\n");
}

static void VbBootTest(void)
{
	ResetMocks();
	VbExEcEnteringMode(0, VB_EC_NORMAL);
	TEST_EQ(VbBootNormal(&ctx), 1002, "VbBootNormal()");
	TEST_EQ(VbGetMode(), VB_EC_NORMAL, "vboot_mode normal");
}

static void VbBootDevTest(void)
{
	int key;

	printf("Testing VbBootDeveloper()...\n");

	/* Proceed after timeout */
	ResetMocks();
	VbExEcEnteringMode(0, VB_EC_DEVELOPER);
	TEST_EQ(VbBootDeveloper(&ctx), 1002, "Timeout");
	TEST_EQ(VbGetMode(), VB_EC_DEVELOPER, "vboot_mode developer");
	TEST_EQ(screens_displayed[0], VB_SCREEN_DEVELOPER_WARNING,
		"  warning screen");
	TEST_EQ(vb2_nv_get(&ctx, VB2_NV_RECOVERY_REQUEST), 0,
		"  recovery reason");
	TEST_EQ(audio_looping_calls_left, 0, "  used up audio");

	/* Proceed to legacy after timeout if GBB flag set */
	ResetMocks();
	sd->gbb_flags |= VB2_GBB_FLAG_DEFAULT_DEV_BOOT_LEGACY |
			VB2_GBB_FLAG_FORCE_DEV_BOOT_LEGACY;
	TEST_EQ(VbBootDeveloper(&ctx), 1002, "Timeout");
	TEST_EQ(vbexlegacy_called, 1, "  try legacy");
	TEST_EQ(altfw_num, 0, "  check altfw_num");

	/* Proceed to legacy after timeout if GBB flag set */
	ResetMocks();
	sd->gbb_flags |= VB2_GBB_FLAG_DEFAULT_DEV_BOOT_LEGACY |
			VB2_GBB_FLAG_FORCE_DEV_BOOT_LEGACY;
	TEST_EQ(VbBootDeveloper(&ctx), 1002, "Timeout");
	TEST_EQ(vbexlegacy_called, 1, "  try legacy");
	TEST_EQ(altfw_num, 0, "  check altfw_num");

	/* Proceed to legacy after timeout if boot legacy and default boot
	 * legacy are set */
	ResetMocks();
	vb2_nv_set(&ctx, VB2_NV_DEV_DEFAULT_BOOT,
		   VB2_DEV_DEFAULT_BOOT_LEGACY);
	vb2_nv_set(&ctx, VB2_NV_DEV_BOOT_LEGACY, 1);
	TEST_EQ(VbBootDeveloper(&ctx), 1002, "Timeout");
	TEST_EQ(vbexlegacy_called, 1, "  try legacy");
	TEST_EQ(altfw_num, 0, "  check altfw_num");

	/* Proceed to legacy boot mode only if enabled */
	ResetMocks();
	vb2_nv_set(&ctx, VB2_NV_DEV_DEFAULT_BOOT,
		   VB2_DEV_DEFAULT_BOOT_LEGACY);
	TEST_EQ(VbBootDeveloper(&ctx), 1002, "Timeout");
	TEST_EQ(vbexlegacy_called, 0, "  not legacy");

	/* Proceed to usb after timeout if boot usb and default boot
	 * usb are set */
	ResetMocks();
	vb2_nv_set(&ctx, VB2_NV_DEV_DEFAULT_BOOT,
		   VB2_DEV_DEFAULT_BOOT_USB);
	vb2_nv_set(&ctx, VB2_NV_DEV_BOOT_USB, 1);
	vbtlk_retval = VBERROR_SUCCESS - VB_DISK_FLAG_REMOVABLE;
	TEST_EQ(VbBootDeveloper(&ctx), 0, "Ctrl+U USB");

	/* Proceed to usb boot mode only if enabled */
	ResetMocks();
	vb2_nv_set(&ctx, VB2_NV_DEV_DEFAULT_BOOT,
		   VB2_DEV_DEFAULT_BOOT_USB);
	TEST_EQ(VbBootDeveloper(&ctx), 1002, "Timeout");

	/* If no USB tries fixed disk */
	ResetMocks();
	vb2_nv_set(&ctx, VB2_NV_DEV_BOOT_USB, 1);
	vb2_nv_set(&ctx, VB2_NV_DEV_DEFAULT_BOOT,
		   VB2_DEV_DEFAULT_BOOT_USB);
	TEST_EQ(VbBootDeveloper(&ctx), 1002, "Ctrl+U enabled");
	TEST_EQ(vbexlegacy_called, 0, "  not legacy");

	/* Up arrow is uninteresting / passed to VbCheckDisplayKey() */
	ResetMocks();
	mock_keypress[0] = VB_KEY_UP;
	TEST_EQ(VbBootDeveloper(&ctx), 1002, "Up arrow");

	/* Shutdown requested in loop */
	ResetMocks();
	shutdown_request_calls_left = 2;
	TEST_EQ(VbBootDeveloper(&ctx),
		VBERROR_SHUTDOWN_REQUESTED,
		"Shutdown requested");
	TEST_NEQ(audio_looping_calls_left, 0, "  aborts audio");

	/* Shutdown requested by keyboard in loop */
	ResetMocks();
	mock_keypress[0] = VB_BUTTON_POWER_SHORT_PRESS;
	TEST_EQ(VbBootDeveloper(&ctx),
		VBERROR_SHUTDOWN_REQUESTED,
		"Shutdown requested by keyboard");

	/* Space goes straight to recovery if no virtual dev switch */
	ResetMocks();
	mock_keypress[0] = ' ';
	TEST_EQ(VbBootDeveloper(&ctx),
		VBERROR_LOAD_KERNEL_RECOVERY,
		"Space = recovery");
	TEST_EQ(vb2_nv_get(&ctx, VB2_NV_RECOVERY_REQUEST),
		VB2_RECOVERY_RW_DEV_SCREEN, "  recovery reason");

	/* Space asks to disable virtual dev switch */
	ResetMocks();
	shared->flags = VBSD_HONOR_VIRT_DEV_SWITCH | VBSD_BOOT_DEV_SWITCH_ON;
	mock_keypress[0] = ' ';
	mock_keypress[1] = VB_KEY_ENTER;
	TEST_EQ(VbBootDeveloper(&ctx), VBERROR_REBOOT_REQUIRED,
		"Space = tonorm");
	TEST_EQ(screens_displayed[0], VB_SCREEN_DEVELOPER_WARNING,
		"  warning screen");
	TEST_EQ(screens_displayed[1], VB_SCREEN_DEVELOPER_TO_NORM,
		"  tonorm screen");
	TEST_EQ(screens_displayed[2], VB_SCREEN_TO_NORM_CONFIRMED,
		"  confirm screen");
	TEST_EQ(vb2_nv_get(&ctx, VB2_NV_DISABLE_DEV_REQUEST), 1,
		"  disable dev request");

	/* Space-space doesn't disable it */
	ResetMocks();
	shared->flags = VBSD_HONOR_VIRT_DEV_SWITCH | VBSD_BOOT_DEV_SWITCH_ON;
	mock_keypress[0] = ' ';
	mock_keypress[1] = ' ';
	mock_keypress[2] = VB_KEY_ESC;
	TEST_EQ(VbBootDeveloper(&ctx), 1002, "Space-space");
	TEST_EQ(screens_displayed[0], VB_SCREEN_DEVELOPER_WARNING,
		"  warning screen");
	TEST_EQ(screens_displayed[1], VB_SCREEN_DEVELOPER_TO_NORM,
		"  tonorm screen");
	TEST_EQ(screens_displayed[2], VB_SCREEN_DEVELOPER_WARNING,
		"  warning screen");

	/* Enter doesn't by default */
	ResetMocks();
	shared->flags = VBSD_HONOR_VIRT_DEV_SWITCH | VBSD_BOOT_DEV_SWITCH_ON;
	mock_keypress[0] = VB_KEY_ENTER;
	mock_keypress[1] = VB_KEY_ENTER;
	TEST_EQ(VbBootDeveloper(&ctx), 1002, "Enter ignored");

	/* Enter does if GBB flag set */
	ResetMocks();
	shared->flags = VBSD_HONOR_VIRT_DEV_SWITCH | VBSD_BOOT_DEV_SWITCH_ON;
	sd->gbb_flags |= VB2_GBB_FLAG_ENTER_TRIGGERS_TONORM;
	mock_keypress[0] = VB_KEY_ENTER;
	mock_keypress[1] = VB_KEY_ENTER;
	TEST_EQ(VbBootDeveloper(&ctx), VBERROR_REBOOT_REQUIRED,
		"Enter = tonorm");

	/* Tonorm ignored if GBB forces dev switch on */
	ResetMocks();
	shared->flags = VBSD_HONOR_VIRT_DEV_SWITCH | VBSD_BOOT_DEV_SWITCH_ON;
	sd->gbb_flags |= VB2_GBB_FLAG_FORCE_DEV_SWITCH_ON;
	mock_keypress[0] = ' ';
	mock_keypress[1] = VB_KEY_ENTER;
	TEST_EQ(VbBootDeveloper(&ctx), 1002,
		"Can't tonorm gbb-dev");

	/* Shutdown requested at tonorm screen */
	ResetMocks();
	shared->flags = VBSD_HONOR_VIRT_DEV_SWITCH | VBSD_BOOT_DEV_SWITCH_ON;
	mock_keypress[0] = ' ';
	shutdown_request_calls_left = 2;
	TEST_EQ(VbBootDeveloper(&ctx),
		VBERROR_SHUTDOWN_REQUESTED,
		"Shutdown requested at tonorm");
	TEST_EQ(screens_displayed[0], VB_SCREEN_DEVELOPER_WARNING,
		"  warning screen");
	TEST_EQ(screens_displayed[1], VB_SCREEN_DEVELOPER_TO_NORM,
		"  tonorm screen");

	/* Shutdown requested by keyboard at tonorm screen */
	ResetMocks();
	shared->flags = VBSD_HONOR_VIRT_DEV_SWITCH | VBSD_BOOT_DEV_SWITCH_ON;
	mock_keypress[0] = VB_BUTTON_POWER_SHORT_PRESS;
	TEST_EQ(VbBootDeveloper(&ctx),
		VBERROR_SHUTDOWN_REQUESTED,
		"Shutdown requested by keyboard at nonorm");

	/* Ctrl+D dismisses warning */
	ResetMocks();
	mock_keypress[0] = VB_KEY_CTRL('D');
	TEST_EQ(VbBootDeveloper(&ctx), 1002, "Ctrl+D");
	TEST_EQ(vb2_nv_get(&ctx, VB2_NV_RECOVERY_REQUEST), 0,
		"  recovery reason");
	TEST_NEQ(audio_looping_calls_left, 0, "  aborts audio");
	TEST_EQ(vbexlegacy_called, 0, "  not legacy");

	/* Ctrl+D doesn't boot legacy even if GBB flag is set */
	ResetMocks();
	mock_keypress[0] = VB_KEY_CTRL('D');
	sd->gbb_flags |= VB2_GBB_FLAG_DEFAULT_DEV_BOOT_LEGACY;
	TEST_EQ(VbBootDeveloper(&ctx), 1002, "Ctrl+D");
	TEST_EQ(vbexlegacy_called, 0, "  not legacy");

	/* Ctrl+L tries legacy boot mode only if enabled */
	ResetMocks();
	mock_keypress[0] = VB_KEY_CTRL('L');
	TEST_EQ(VbBootDeveloper(&ctx), 1002, "Ctrl+L normal");
	TEST_EQ(vbexlegacy_called, 0, "  not legacy");

	/* Enter altfw menu and time out */
	ResetMocks();
	shutdown_request_calls_left = 1000;
	sd->gbb_flags |= VB2_GBB_FLAG_FORCE_DEV_BOOT_LEGACY;
	mock_keypress[0] = VB_KEY_CTRL('L');
	TEST_EQ(VbBootDeveloper(&ctx), VBERROR_SHUTDOWN_REQUESTED,
		"Ctrl+L force legacy");
	TEST_EQ(vbexlegacy_called, 0, "  try legacy");

	/* Enter altfw menu and select firmware 0 */
	ResetMocks();
	sd->gbb_flags |= VB2_GBB_FLAG_FORCE_DEV_BOOT_LEGACY;
	mock_keypress[0] = VB_KEY_CTRL('L');
	mock_keypress[1] = '0';
	TEST_EQ(VbBootDeveloper(&ctx), 1002,
		"Ctrl+L force legacy");
	TEST_EQ(vbexlegacy_called, 1, "  try legacy");
	TEST_EQ(altfw_num, 0, "  check altfw_num");

	/* Enter altfw menu and then exit it */
	ResetMocks();
	vb2_nv_set(&ctx, VB2_NV_DEV_BOOT_LEGACY, 1);
	mock_keypress[0] = VB_KEY_CTRL('L');
	mock_keypress[1] = VB_KEY_ESC;
	TEST_EQ(VbBootDeveloper(&ctx), 1002,
		"Ctrl+L nv legacy");
	TEST_EQ(vbexlegacy_called, 0, "  try legacy");

	/* Enter altfw menu and select firmware 0 */
	ResetMocks();
	vb2_nv_set(&ctx, VB2_NV_DEV_BOOT_LEGACY, 1);
	mock_keypress[0] = VB_KEY_CTRL('L');
	mock_keypress[1] = '0';
	TEST_EQ(VbBootDeveloper(&ctx), 1002,
		"Ctrl+L nv legacy");
	TEST_EQ(vbexlegacy_called, 1, "  try legacy");
	TEST_EQ(altfw_num, 0, "  check altfw_num");

	/* Enter altfw menu and select firmware 0 */
	ResetMocks();
	VbApiKernelGetFwmp()->flags |= FWMP_DEV_ENABLE_LEGACY;
	mock_keypress[0] = VB_KEY_CTRL('L');
	mock_keypress[1] = '0';
	TEST_EQ(VbBootDeveloper(&ctx), 1002,
		"Ctrl+L fwmp legacy");
	TEST_EQ(vbexlegacy_called, 1, "  fwmp legacy");
	TEST_EQ(altfw_num, 0, "  check altfw_num");

	/* Pressing 1-9 boots alternative firmware only if enabled */
	for (key = '1'; key <= '9'; key++) {
		ResetMocks();
		mock_keypress[0] = key;
		TEST_EQ(VbBootDeveloper(&ctx), 1002, "'1' normal");
		TEST_EQ(vbexlegacy_called, 0, "  not legacy");

		ResetMocks();
		sd->gbb_flags |= VB2_GBB_FLAG_FORCE_DEV_BOOT_LEGACY;
		mock_keypress[0] = key;
		TEST_EQ(VbBootDeveloper(&ctx), 1002,
			"Ctrl+L force legacy");
		TEST_EQ(vbexlegacy_called, 1, "  try legacy");
		TEST_EQ(altfw_num, key - '0', "  check altfw_num");

		ResetMocks();
		vb2_nv_set(&ctx, VB2_NV_DEV_BOOT_LEGACY, 1);
		mock_keypress[0] = key;
		TEST_EQ(VbBootDeveloper(&ctx), 1002,
			"Ctrl+L nv legacy");
		TEST_EQ(vbexlegacy_called, 1, "  try legacy");
		TEST_EQ(altfw_num, key - '0', "  check altfw_num");

		ResetMocks();
		VbApiKernelGetFwmp()->flags |= FWMP_DEV_ENABLE_LEGACY;
		mock_keypress[0] = key;
		TEST_EQ(VbBootDeveloper(&ctx), 1002,
			"Ctrl+L fwmp legacy");
		TEST_EQ(vbexlegacy_called, 1, "  fwmp legacy");
		TEST_EQ(altfw_num, key - '0', "  check altfw_num");
	}

	/* Ctrl+U boots USB only if enabled */
	ResetMocks();
	mock_keypress[0] = VB_KEY_CTRL('U');
	TEST_EQ(VbBootDeveloper(&ctx), 1002, "Ctrl+U normal");

	/* Ctrl+U enabled, with good USB boot */
	ResetMocks();
	vb2_nv_set(&ctx, VB2_NV_DEV_BOOT_USB, 1);
	mock_keypress[0] = VB_KEY_CTRL('U');
	vbtlk_retval = VBERROR_SUCCESS - VB_DISK_FLAG_REMOVABLE;
	TEST_EQ(VbBootDeveloper(&ctx), 0, "Ctrl+U USB");

	/* Ctrl+U enabled via GBB */
	ResetMocks();
	sd->gbb_flags |= VB2_GBB_FLAG_FORCE_DEV_BOOT_USB;
	mock_keypress[0] = VB_KEY_CTRL('U');
	vbtlk_retval = VBERROR_SUCCESS - VB_DISK_FLAG_REMOVABLE;
	TEST_EQ(VbBootDeveloper(&ctx), 0, "Ctrl+U force USB");

	/* Ctrl+U enabled via FWMP */
	ResetMocks();
	VbApiKernelGetFwmp()->flags |= FWMP_DEV_ENABLE_USB;
	mock_keypress[0] = VB_KEY_CTRL('U');
	vbtlk_retval = VBERROR_SUCCESS - VB_DISK_FLAG_REMOVABLE;
	TEST_EQ(VbBootDeveloper(&ctx), 0, "Ctrl+U force USB");

	/* Ctrl+S set vendor data and reboot */
	ResetMocks();
	ctx.flags |= VB2_CONTEXT_VENDOR_DATA_SETTABLE;
	mock_keypress[0] = VB_KEY_CTRL('S');
	mock_keypress[1] = '4';
	mock_keypress[2] = '3';
	mock_keypress[3] = '2';
	mock_keypress[4] = '1';
	mock_keypress[5] = VB_KEY_ENTER; // Set vendor data
	mock_keypress[6] = VB_KEY_ENTER; // Confirm vendor data
	TEST_EQ(VbBootDeveloper(&ctx), VBERROR_REBOOT_REQUIRED,
		"Ctrl+S set vendor data and reboot");
	TEST_EQ(set_vendor_data_called, 1, "  VbExSetVendorData() called");
	TEST_STR_EQ(set_vendor_data, "4321", "  Vendor data correct");

	/* Ctrl+S extra keys ignored */
	ResetMocks();
	ctx.flags |= VB2_CONTEXT_VENDOR_DATA_SETTABLE;
	mock_keypress[0] = VB_KEY_CTRL('S');
	mock_keypress[1] = '4';
	mock_keypress[2] = '3';
	mock_keypress[3] = '2';
	mock_keypress[4] = '1';
	mock_keypress[5] = '5';
	mock_keypress[6] = VB_KEY_ENTER; // Set vendor data
	mock_keypress[7] = VB_KEY_ENTER; // Confirm vendor data
	TEST_EQ(VbBootDeveloper(&ctx), VBERROR_REBOOT_REQUIRED,
		"Ctrl+S extra keys ignored");
	TEST_EQ(set_vendor_data_called, 1, "  VbExSetVendorData() called");
	TEST_STR_EQ(set_vendor_data, "4321", "  Vendor data correct");

	/* Ctrl+S converts case */
	ResetMocks();
	ctx.flags |= VB2_CONTEXT_VENDOR_DATA_SETTABLE;
	mock_keypress[0] = VB_KEY_CTRL('S');
	mock_keypress[1] = 'a';
	mock_keypress[2] = 'B';
	mock_keypress[3] = 'Y';
	mock_keypress[4] = 'z';
	mock_keypress[5] = VB_KEY_ENTER; // Set vendor data
	mock_keypress[6] = VB_KEY_ENTER; // Confirm vendor data
	TEST_EQ(VbBootDeveloper(&ctx), VBERROR_REBOOT_REQUIRED,
		"Ctrl+S converts case");
	TEST_EQ(set_vendor_data_called, 1, "  VbExSetVendorData() called");
	TEST_STR_EQ(set_vendor_data, "ABYZ", "  Vendor data correct");

	/* Ctrl+S backspace works */
	ResetMocks();
	ctx.flags |= VB2_CONTEXT_VENDOR_DATA_SETTABLE;
	mock_keypress[0] = VB_KEY_CTRL('S');
	mock_keypress[1] = 'A';
	mock_keypress[2] = 'B';
	mock_keypress[3] = 'C';
	mock_keypress[4] = VB_KEY_BACKSPACE;
	mock_keypress[5] = VB_KEY_BACKSPACE;
	mock_keypress[6] = '3';
	mock_keypress[7] = '2';
	mock_keypress[8] = '1';
	mock_keypress[9] = VB_KEY_ENTER; // Set vendor data
	mock_keypress[10] = VB_KEY_ENTER; // Confirm vendor data
	TEST_EQ(VbBootDeveloper(&ctx), VBERROR_REBOOT_REQUIRED,
		"Ctrl+S backspace works");
	TEST_EQ(set_vendor_data_called, 1, "  VbExSetVendorData() called");
	TEST_STR_EQ(set_vendor_data, "A321", "  Vendor data correct");

	/* Ctrl+S invalid chars don't print */
	ResetMocks();
	ctx.flags |= VB2_CONTEXT_VENDOR_DATA_SETTABLE;
	mock_keypress[0] = VB_KEY_CTRL('S');
	mock_keypress[1] = '4';
	mock_keypress[2] = '-';
	mock_keypress[3] = '^';
	mock_keypress[4] = '&';
	mock_keypress[5] = '$';
	mock_keypress[6] = '.';
	mock_keypress[7] = '3';
	mock_keypress[8] = '2';
	mock_keypress[9] = '1';
	mock_keypress[10] = VB_KEY_ENTER; // Set vendor data
	mock_keypress[11] = VB_KEY_ENTER; // Confirm vendor data
	TEST_EQ(VbBootDeveloper(&ctx), VBERROR_REBOOT_REQUIRED,
		"Ctrl+S invalid chars don't print");
	TEST_EQ(set_vendor_data_called, 1, "  VbExSetVendorData() called");
	TEST_STR_EQ(set_vendor_data, "4321", "  Vendor data correct");

	/* Ctrl+S invalid chars don't print with backspace */
	ResetMocks();
	ctx.flags |= VB2_CONTEXT_VENDOR_DATA_SETTABLE;
	mock_keypress[0] = VB_KEY_CTRL('S');
	mock_keypress[1] = '4';
	mock_keypress[2] = '-';
	mock_keypress[3] = VB_KEY_BACKSPACE; // Should delete 4
	mock_keypress[4] = '3';
	mock_keypress[5] = '2';
	mock_keypress[6] = '1';
	mock_keypress[7] = '0';
	mock_keypress[8] = VB_KEY_ENTER; // Set vendor data
	mock_keypress[9] = VB_KEY_ENTER; // Confirm vendor data
	TEST_EQ(VbBootDeveloper(&ctx), VBERROR_REBOOT_REQUIRED,
		"Ctrl+S invalid chars don't print with backspace");
	TEST_EQ(set_vendor_data_called, 1, "  VbExSetVendorData() called");
	TEST_STR_EQ(set_vendor_data, "3210", "  Vendor data correct");

	/* Ctrl+S backspace only doesn't underrun */
	ResetMocks();
	ctx.flags |= VB2_CONTEXT_VENDOR_DATA_SETTABLE;
	mock_keypress[0] = VB_KEY_CTRL('S');
	mock_keypress[1] = 'A';
	mock_keypress[2] = VB_KEY_BACKSPACE;
	mock_keypress[3] = VB_KEY_BACKSPACE;
	mock_keypress[4] = '4';
	mock_keypress[5] = '3';
	mock_keypress[6] = '2';
	mock_keypress[7] = '1';
	mock_keypress[8] = VB_KEY_ENTER; // Set vendor data
	mock_keypress[9] = VB_KEY_ENTER; // Confirm vendor data
	TEST_EQ(VbBootDeveloper(&ctx), VBERROR_REBOOT_REQUIRED,
		"Ctrl+S backspace only doesn't underrun");
	TEST_EQ(set_vendor_data_called, 1, "  VbExSetVendorData() called");
	TEST_STR_EQ(set_vendor_data, "4321", "  Vendor data correct");

	/* Ctrl+S too short */
	ResetMocks();
	ctx.flags |= VB2_CONTEXT_VENDOR_DATA_SETTABLE;
	mock_keypress[0] = VB_KEY_CTRL('S');
	mock_keypress[1] = '1';
	mock_keypress[2] = '2';
	mock_keypress[3] = '3';
	mock_keypress[4] = VB_KEY_ENTER; // Set vendor data (Nothing happens)
	mock_keypress[5] = VB_KEY_ENTER; // Confirm vendor data (Nothing happens)
	mock_keypress[6] = VB_KEY_ESC;
	TEST_EQ(VbBootDeveloper(&ctx), 1002, "Ctrl+S too short");
	TEST_EQ(set_vendor_data_called, 0, "  VbExSetVendorData() not called");

	/* Ctrl+S esc from set screen */
	ResetMocks();
	ctx.flags |= VB2_CONTEXT_VENDOR_DATA_SETTABLE;
	mock_keypress[0] = VB_KEY_CTRL('S');
	mock_keypress[1] = VB_KEY_ESC;
	TEST_EQ(VbBootDeveloper(&ctx), 1002, "Ctrl+S esc from set screen");
	TEST_EQ(set_vendor_data_called, 0, "  VbExSetVendorData() not called");

	/* Ctrl+S esc from set screen with tag */
	ResetMocks();
	ctx.flags |= VB2_CONTEXT_VENDOR_DATA_SETTABLE;
	mock_keypress[0] = VB_KEY_CTRL('S');
	mock_keypress[1] = '4';
	mock_keypress[2] = '3';
	mock_keypress[3] = '2';
	mock_keypress[4] = '1';
	mock_keypress[5] = VB_KEY_ESC;
	TEST_EQ(VbBootDeveloper(&ctx), 1002,
		"Ctrl+S esc from set screen with tag");
	TEST_EQ(set_vendor_data_called, 0, "  VbExSetVendorData() not called");

	/* Ctrl+S esc from confirm screen */
	ResetMocks();
	ctx.flags |= VB2_CONTEXT_VENDOR_DATA_SETTABLE;
	mock_keypress[0] = VB_KEY_CTRL('S');
	mock_keypress[1] = '4';
	mock_keypress[2] = '3';
	mock_keypress[3] = '2';
	mock_keypress[4] = '1';
	mock_keypress[5] = VB_KEY_ENTER; // Set vendor data
	mock_keypress[6] = VB_KEY_ESC;
	TEST_EQ(VbBootDeveloper(&ctx), 1002, "Ctrl+S esc from set screen");
	TEST_EQ(set_vendor_data_called, 0, "  VbExSetVendorData() not called");

	/* If no USB, eventually times out and tries fixed disk */
	ResetMocks();
	vb2_nv_set(&ctx, VB2_NV_DEV_BOOT_USB, 1);
	mock_keypress[0] = VB_KEY_CTRL('U');
	TEST_EQ(VbBootDeveloper(&ctx), 1002, "Ctrl+U enabled");
	TEST_EQ(vbexlegacy_called, 0, "  not legacy");
	TEST_EQ(vb2_nv_get(&ctx, VB2_NV_RECOVERY_REQUEST), 0,
		"  recovery reason");
	TEST_EQ(audio_looping_calls_left, 0, "  used up audio");

	/* If dev mode is disabled, goes to TONORM screen repeatedly */
	ResetMocks();
	VbApiKernelGetFwmp()->flags |= FWMP_DEV_DISABLE_BOOT;
	mock_keypress[0] = VB_KEY_ESC;  /* Just causes TONORM again */
	mock_keypress[1] = VB_KEY_ENTER;
	TEST_EQ(VbBootDeveloper(&ctx), VBERROR_REBOOT_REQUIRED,
		"FWMP dev disabled");
	TEST_EQ(screens_displayed[0], VB_SCREEN_DEVELOPER_TO_NORM,
		"  tonorm screen");
	TEST_EQ(screens_displayed[1], VB_SCREEN_DEVELOPER_TO_NORM,
		"  tonorm screen");
	TEST_EQ(screens_displayed[2], VB_SCREEN_TO_NORM_CONFIRMED,
		"  confirm screen");
	TEST_EQ(vb2_nv_get(&ctx, VB2_NV_DISABLE_DEV_REQUEST), 1,
		"  disable dev request");

	/* Shutdown requested when dev disabled */
	ResetMocks();
	shared->flags = VBSD_HONOR_VIRT_DEV_SWITCH | VBSD_BOOT_DEV_SWITCH_ON;
	VbApiKernelGetFwmp()->flags |= FWMP_DEV_DISABLE_BOOT;
	shutdown_request_calls_left = 1;
	TEST_EQ(VbBootDeveloper(&ctx),
		VBERROR_SHUTDOWN_REQUESTED,
		"Shutdown requested when dev disabled");
	TEST_EQ(screens_displayed[0], VB_SCREEN_DEVELOPER_TO_NORM,
		"  tonorm screen");

	/* Shutdown requested by keyboard when dev disabled */
	ResetMocks();
	shared->flags = VBSD_HONOR_VIRT_DEV_SWITCH | VBSD_BOOT_DEV_SWITCH_ON;
	VbApiKernelGetFwmp()->flags |= FWMP_DEV_DISABLE_BOOT;
	mock_keypress[0] = VB_BUTTON_POWER_SHORT_PRESS;
	TEST_EQ(VbBootDeveloper(&ctx),
		VBERROR_SHUTDOWN_REQUESTED,
		"Shutdown requested by keyboard when dev disabled");

	printf("...done.\n");
}

static void VbBootRecTest(void)
{
	printf("Testing VbBootRecovery()...\n");

	/* Shutdown requested in loop */
	ResetMocks();
	shutdown_request_calls_left = 10;
	VbExEcEnteringMode(0, VB_EC_RECOVERY);
	TEST_EQ(VbBootRecovery(&ctx),
		VBERROR_SHUTDOWN_REQUESTED,
		"Shutdown requested");
	TEST_EQ(VbGetMode(), VB_EC_RECOVERY, "vboot_mode recovery");

	TEST_EQ(vb2_nv_get(&ctx, VB2_NV_RECOVERY_REQUEST), 0,
		"  recovery reason");
	TEST_EQ(screens_displayed[0], VB_SCREEN_OS_BROKEN,
		"  broken screen");

	/* Shutdown requested by keyboard */
	ResetMocks();
	VbExEcEnteringMode(0, VB_EC_RECOVERY);
	mock_keypress[0] = VB_BUTTON_POWER_SHORT_PRESS;
	TEST_EQ(VbBootRecovery(&ctx),
		VBERROR_SHUTDOWN_REQUESTED,
		"Shutdown requested by keyboard");

	/* Ignore power button held on boot */
	ResetMocks();
	shutdown_request_calls_left = 100;
	shutdown_request_power_held = 1;
	shared->flags = VBSD_BOOT_REC_SWITCH_ON;
	trust_ec = 1;
	vbtlk_retval = VBERROR_NO_DISK_FOUND - VB_DISK_FLAG_REMOVABLE;
	TEST_EQ(VbBootRecovery(&ctx),
		VBERROR_SHUTDOWN_REQUESTED,
		"Ignore power button held on boot");
	TEST_EQ(screens_displayed[0], VB_SCREEN_RECOVERY_INSERT,
		"  insert screen");
	/*
	 * shutdown_request_power_held holds power button for 10 calls, then
	 * releases for 10, then holds again, so expect shutdown after 20:
	 * 100 - 20 = 80.
	 */
	TEST_EQ(shutdown_request_calls_left, 80,
		"  ignore held button");

	/* Broken screen */
	ResetMocks();
	shutdown_request_calls_left = 100;
	mock_num_disks[0] = 1;
	mock_num_disks[1] = 1;
	mock_num_disks[2] = 1;
	vbtlk_retval = VBERROR_NO_DISK_FOUND - VB_DISK_FLAG_REMOVABLE;
	TEST_EQ(VbBootRecovery(&ctx),
		VBERROR_SHUTDOWN_REQUESTED,
		"Broken");
	TEST_EQ(screens_displayed[0], VB_SCREEN_OS_BROKEN,
		"  broken screen");

	/* Broken screen even if dev switch is on */
	ResetMocks();
	shutdown_request_calls_left = 100;
	mock_num_disks[0] = 1;
	mock_num_disks[1] = 1;
	shared->flags |= VBSD_BOOT_DEV_SWITCH_ON;
	vbtlk_retval = VBERROR_NO_DISK_FOUND - VB_DISK_FLAG_REMOVABLE;
	TEST_EQ(VbBootRecovery(&ctx),
		VBERROR_SHUTDOWN_REQUESTED,
		"Broken (dev)");
	TEST_EQ(screens_displayed[0], VB_SCREEN_OS_BROKEN,
		"  broken screen");

	/* Force insert screen with GBB flag */
	ResetMocks();
	shutdown_request_calls_left = 100;
	sd->gbb_flags |= VB2_GBB_FLAG_FORCE_MANUAL_RECOVERY;
	vbtlk_retval = VBERROR_NO_DISK_FOUND - VB_DISK_FLAG_REMOVABLE;
	TEST_EQ(VbBootRecovery(&ctx),
		VBERROR_SHUTDOWN_REQUESTED,
		"Insert (forced by GBB)");
	TEST_EQ(screens_displayed[0], VB_SCREEN_RECOVERY_INSERT,
		"  insert screen");

	/* No removal if recovery button physically pressed */
	ResetMocks();
	shutdown_request_calls_left = 100;
	mock_num_disks[0] = 1;
	mock_num_disks[1] = 1;
	shared->flags |= VBSD_BOOT_REC_SWITCH_ON;
	vbtlk_retval = VBERROR_NO_DISK_FOUND - VB_DISK_FLAG_REMOVABLE;
	TEST_EQ(VbBootRecovery(&ctx),
		VBERROR_SHUTDOWN_REQUESTED,
		"No remove in rec");
	TEST_EQ(screens_displayed[0], VB_SCREEN_OS_BROKEN,
		"  broken screen");

	/* Removal if no disk initially found, but found on second attempt */
	ResetMocks();
	shutdown_request_calls_left = 100;
	mock_num_disks[0] = 0;
	mock_num_disks[1] = 1;
	vbtlk_retval = VBERROR_NO_DISK_FOUND - VB_DISK_FLAG_REMOVABLE;
	TEST_EQ(VbBootRecovery(&ctx),
		VBERROR_SHUTDOWN_REQUESTED,
		"Remove");
	TEST_EQ(screens_displayed[0], VB_SCREEN_OS_BROKEN,
		"  broken screen");

	/* Bad disk count doesn't require removal */
	ResetMocks();
	shutdown_request_calls_left = 100;
	mock_num_disks[0] = -1;
	vbtlk_retval = VBERROR_NO_DISK_FOUND - VB_DISK_FLAG_REMOVABLE;
	shutdown_request_calls_left = 10;
	TEST_EQ(VbBootRecovery(&ctx),
		VBERROR_SHUTDOWN_REQUESTED,
		"Bad disk count");
	TEST_EQ(screens_displayed[0], VB_SCREEN_OS_BROKEN,
		"  broken screen");

	/* Ctrl+D ignored for many reasons... */
	ResetMocks();
	shared->flags = VBSD_HONOR_VIRT_DEV_SWITCH | VBSD_BOOT_REC_SWITCH_ON;
	shutdown_request_calls_left = 100;
	mock_keypress[0] = VB_KEY_CTRL('D');
	trust_ec = 0;
	TEST_EQ(VbBootRecovery(&ctx),
		VBERROR_SHUTDOWN_REQUESTED,
		"Ctrl+D ignored if EC not trusted");
	TEST_EQ(virtdev_set, 0, "  virtual dev mode off");
	TEST_NEQ(screens_displayed[1], VB_SCREEN_RECOVERY_TO_DEV,
		 "  todev screen");

	ResetMocks();
	shared->flags = VBSD_HONOR_VIRT_DEV_SWITCH | VBSD_BOOT_REC_SWITCH_ON |
		VBSD_BOOT_DEV_SWITCH_ON;
	trust_ec = 1;
	shutdown_request_calls_left = 100;
	mock_keypress[0] = VB_KEY_CTRL('D');
	TEST_EQ(VbBootRecovery(&ctx),
		VBERROR_SHUTDOWN_REQUESTED,
		"Ctrl+D ignored if already in dev mode");
	TEST_EQ(virtdev_set, 0, "  virtual dev mode off");
	TEST_NEQ(screens_displayed[1], VB_SCREEN_RECOVERY_TO_DEV,
		 "  todev screen");

	ResetMocks();
	shared->flags = VBSD_HONOR_VIRT_DEV_SWITCH;
	trust_ec = 1;
	shutdown_request_calls_left = 100;
	mock_keypress[0] = VB_KEY_CTRL('D');
	TEST_EQ(VbBootRecovery(&ctx),
		VBERROR_SHUTDOWN_REQUESTED,
		"Ctrl+D ignored if recovery not manually triggered");
	TEST_EQ(virtdev_set, 0, "  virtual dev mode off");
	TEST_NEQ(screens_displayed[1], VB_SCREEN_RECOVERY_TO_DEV,
		 "  todev screen");

	ResetMocks();
	shared->flags = VBSD_BOOT_REC_SWITCH_ON;
	trust_ec = 1;
	shutdown_request_calls_left = 100;
	mock_keypress[0] = VB_KEY_CTRL('D');
	TEST_EQ(VbBootRecovery(&ctx),
		VBERROR_SHUTDOWN_REQUESTED,
		"Ctrl+D ignored if no virtual dev switch");
	TEST_EQ(virtdev_set, 0, "  virtual dev mode off");
	TEST_NEQ(screens_displayed[1], VB_SCREEN_RECOVERY_TO_DEV,
		 "  todev screen");

	/* Ctrl+D ignored because the physical recovery switch is still pressed
	 * and we don't like that.
	 */
	ResetMocks();
	shared->flags = VBSD_BOOT_REC_SWITCH_ON;
	trust_ec = 1;
	shutdown_request_calls_left = 100;
	mock_keypress[0] = VB_KEY_CTRL('D');
	mock_switches[0] = VB_SWITCH_FLAG_REC_BUTTON_PRESSED;
	TEST_EQ(VbBootRecovery(&ctx),
		VBERROR_SHUTDOWN_REQUESTED,
		"Ctrl+D ignored if phys rec button is still pressed");
	TEST_NEQ(screens_displayed[1], VB_SCREEN_RECOVERY_TO_DEV,
		 "  todev screen");

	/* Ctrl+D then space means don't enable */
	ResetMocks();
	shared->flags = VBSD_HONOR_VIRT_DEV_SWITCH | VBSD_BOOT_REC_SWITCH_ON;
	shutdown_request_calls_left = 100;
	vbtlk_retval = VBERROR_NO_DISK_FOUND - VB_DISK_FLAG_REMOVABLE;
	trust_ec = 1;
	mock_keypress[0] = VB_KEY_CTRL('D');
	mock_keypress[1] = ' ';
	TEST_EQ(VbBootRecovery(&ctx),
		VBERROR_SHUTDOWN_REQUESTED,
		"Ctrl+D todev abort");
	TEST_EQ(screens_displayed[0], VB_SCREEN_RECOVERY_INSERT,
		"  insert screen");
	TEST_EQ(screens_displayed[1], VB_SCREEN_RECOVERY_TO_DEV,
		"  todev screen");
	TEST_EQ(screens_displayed[2], VB_SCREEN_RECOVERY_INSERT,
		"  insert screen");
	TEST_EQ(virtdev_set, 0, "  virtual dev mode off");

	/* Ctrl+D then enter means enable */
	ResetMocks();
	shared->flags = VBSD_HONOR_VIRT_DEV_SWITCH | VBSD_BOOT_REC_SWITCH_ON;
	shutdown_request_calls_left = 100;
	vbtlk_retval = VBERROR_NO_DISK_FOUND - VB_DISK_FLAG_REMOVABLE;
	trust_ec = 1;
	mock_keypress[0] = VB_KEY_CTRL('D');
	mock_keypress[1] = VB_KEY_ENTER;
	mock_keyflags[1] = VB_KEY_FLAG_TRUSTED_KEYBOARD;
	TEST_EQ(VbBootRecovery(&ctx), VBERROR_EC_REBOOT_TO_RO_REQUIRED,
		"Ctrl+D todev confirm");
	TEST_EQ(virtdev_set, 1, "  virtual dev mode on");

	/* Handle TPM error in enabling dev mode */
	ResetMocks();
	shared->flags = VBSD_HONOR_VIRT_DEV_SWITCH | VBSD_BOOT_REC_SWITCH_ON;
	shutdown_request_calls_left = 100;
	vbtlk_retval = VBERROR_NO_DISK_FOUND - VB_DISK_FLAG_REMOVABLE;
	trust_ec = 1;
	mock_keypress[0] = VB_KEY_CTRL('D');
	mock_keypress[1] = VB_KEY_ENTER;
	mock_keyflags[1] = VB_KEY_FLAG_TRUSTED_KEYBOARD;
	virtdev_retval = VBERROR_SIMULATED;
	TEST_EQ(VbBootRecovery(&ctx),
		VBERROR_TPM_SET_BOOT_MODE_STATE,
		"Ctrl+D todev failure");

	/* Test Diagnostic Mode via Ctrl-C when no oprom needed */
	ResetMocks();
	shared->flags = VBSD_BOOT_REC_SWITCH_ON;
	trust_ec = 1;
	shutdown_request_calls_left = 100;
	mock_keypress[0] = 0x03;
	TEST_EQ(vb2_nv_get(&ctx, VB2_NV_DIAG_REQUEST), 0,
		"todiag is zero");
	if (DIAGNOSTIC_UI)
		TEST_EQ(VbBootRecovery(&ctx),
			VBERROR_REBOOT_REQUIRED,
			"Ctrl+C todiag - enabled");
	else
		TEST_EQ(VbBootRecovery(&ctx),
			VBERROR_SHUTDOWN_REQUESTED,
			"Ctrl+C todiag - disabled");
	TEST_EQ(vb2_nv_get(&ctx, VB2_NV_DIAG_REQUEST), DIAGNOSTIC_UI,
		"todiag is updated for Ctrl-C");
	TEST_EQ(vb2_nv_get(&ctx, VB2_NV_OPROM_NEEDED), 0,
		"todiag doesn't update for unneeded opom");

	/* Test Diagnostic Mode via F12 - oprom needed */
	ResetMocks();
	shared->flags = VBSD_BOOT_REC_SWITCH_ON | VBSD_OPROM_MATTERS;
	trust_ec = 1;
	shutdown_request_calls_left = 100;
	mock_keypress[0] = 0x114;
	TEST_EQ(vb2_nv_get(&ctx, VB2_NV_DIAG_REQUEST), 0,
		"todiag is zero");
	if (DIAGNOSTIC_UI)
		TEST_EQ(VbBootRecovery(&ctx),
			VBERROR_REBOOT_REQUIRED,
			"F12 todiag - enabled");
	else
		TEST_EQ(VbBootRecovery(&ctx),
			VBERROR_SHUTDOWN_REQUESTED,
			"F12 todiag - disabled");
	TEST_EQ(vb2_nv_get(&ctx, VB2_NV_DIAG_REQUEST), DIAGNOSTIC_UI,
		"todiag is updated for F12");
	TEST_EQ(vb2_nv_get(&ctx, VB2_NV_OPROM_NEEDED), DIAGNOSTIC_UI,
		"todiag updates opom, if need");

	printf("...done.\n");
}

static void VbBootDiagTest(void)
{
	printf("Testing VbBootDiagnostic()...\n");

	/* No key pressed - timeout. */
	ResetMocks();
	TEST_EQ(VbBootDiagnostic(&ctx), VBERROR_REBOOT_REQUIRED, "Timeout");
	TEST_EQ(screens_displayed[0], VB_SCREEN_CONFIRM_DIAG,
		"  confirm screen");
	TEST_EQ(screens_displayed[1], VB_SCREEN_BLANK,
		"  blank screen");
	TEST_EQ(tpm_set_mode_called, 0, "  no tpm call");
	TEST_EQ(vbexlegacy_called, 0, "  not legacy");
	TEST_EQ(current_ticks, 30 * VB_USEC_PER_SEC,
		"  waited for 30 seconds");

	/* Esc key pressed. */
	ResetMocks();
	mock_keypress[0] = VB_KEY_ESC;
	TEST_EQ(VbBootDiagnostic(&ctx), VBERROR_REBOOT_REQUIRED, "Esc key");
	TEST_EQ(screens_displayed[0], VB_SCREEN_CONFIRM_DIAG,
		"  confirm screen");
	TEST_EQ(screens_displayed[1], VB_SCREEN_BLANK,
		"  blank screen");
	TEST_EQ(tpm_set_mode_called, 0, "  no tpm call");
	TEST_EQ(vbexlegacy_called, 0, "  not legacy");
	TEST_EQ(current_ticks, 0, "  didn't wait at all");

	/* Shutdown requested via lid close */
	ResetMocks();
	shutdown_via_lid_close = 1;
	shutdown_request_calls_left = 10;
	TEST_EQ(VbBootDiagnostic(&ctx), VBERROR_SHUTDOWN_REQUESTED, "Shutdown");
	TEST_EQ(screens_displayed[0], VB_SCREEN_CONFIRM_DIAG,
		"  confirm screen");
	TEST_EQ(screens_displayed[1], VB_SCREEN_BLANK,
		"  blank screen");
	TEST_EQ(tpm_set_mode_called, 0, "  no tpm call");
	TEST_EQ(vbexlegacy_called, 0, "  not legacy");
	TEST_TRUE(current_ticks < VB_USEC_PER_SEC, "  didn't wait long");

	/* Power button pressed but not released. */
	ResetMocks();
	mock_switches_are_stuck = 1;
	mock_switches[0] = VB_SWITCH_FLAG_PHYS_PRESENCE_PRESSED;
	TEST_EQ(VbBootDiagnostic(&ctx), VBERROR_REBOOT_REQUIRED, "Power held");
	TEST_EQ(screens_displayed[0], VB_SCREEN_CONFIRM_DIAG,
		"  confirm screen");
	TEST_EQ(screens_displayed[1], VB_SCREEN_BLANK,
		"  blank screen");
	TEST_EQ(tpm_set_mode_called, 0, "  no tpm call");
	TEST_EQ(vbexlegacy_called, 0, "  not legacy");

	/* Power button is pressed and released. */
	ResetMocks();
	mock_switches[0] = 0;
	mock_switches[1] = VB_SWITCH_FLAG_PHYS_PRESENCE_PRESSED;
	mock_switches[2] = 0;
	TEST_EQ(VbBootDiagnostic(&ctx), VBERROR_REBOOT_REQUIRED, "Confirm");
	TEST_EQ(screens_displayed[0], VB_SCREEN_CONFIRM_DIAG,
		"  confirm screen");
	TEST_EQ(screens_displayed[1], VB_SCREEN_BLANK,
		"  blank screen");
	TEST_EQ(tpm_set_mode_called, 1, "  tpm call");
	TEST_EQ(tpm_mode, VB2_TPM_MODE_DISABLED, "  tpm disabled");
	TEST_EQ(vbexlegacy_called, 1, "  legacy");
	TEST_EQ(altfw_num, VB_ALTFW_DIAGNOSTIC, "  check altfw_num");
	/*
	 * Ideally we'd that no recovery request was recorded, but
	 * VbExLegacy() can only fail or crash the tests.
	 */
	TEST_EQ(vb2_nv_get(&ctx, VB2_NV_RECOVERY_REQUEST),
		VB2_RECOVERY_ALTFW_HASH_FAILED,
		"  recovery request");

        /* Power button confirm, but now with a tpm failure. */
	ResetMocks();
	tpm_mode = VB2_TPM_MODE_DISABLED;
	mock_switches[0] = 0;
	mock_switches[1] = VB_SWITCH_FLAG_PHYS_PRESENCE_PRESSED;
	mock_switches[2] = 0;
	TEST_EQ(VbBootDiagnostic(&ctx), VBERROR_REBOOT_REQUIRED,
		"Confirm but tpm fail");
	TEST_EQ(screens_displayed[0], VB_SCREEN_CONFIRM_DIAG,
		"  confirm screen");
	TEST_EQ(screens_displayed[1], VB_SCREEN_BLANK,
		"  blank screen");
	TEST_EQ(tpm_set_mode_called, 1, "  tpm call");
	TEST_EQ(tpm_mode, VB2_TPM_MODE_DISABLED, "  tpm disabled");
	TEST_EQ(vbexlegacy_called, 0, "  legacy not called");
	TEST_EQ(vb2_nv_get(&ctx, VB2_NV_RECOVERY_REQUEST),
		VB2_RECOVERY_TPM_DISABLE_FAILED,
		"  recovery request");

	printf("...done.\n");
}


int main(void)
{
	VbUserConfirmsTest();
	VbBootTest();
	VbBootDevTest();
	VbBootRecTest();
	if (DIAGNOSTIC_UI)
		VbBootDiagTest();

	return gTestSuccess ? 0 : 255;
}
