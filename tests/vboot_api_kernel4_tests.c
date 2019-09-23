/* Copyright (c) 2013 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Tests for vboot_api_kernel, part 4 - select and load kernel
 */

#include "2api.h"
#include "2common.h"
#include "2misc.h"
#include "2nvstorage.h"
#include "2secdata.h"
#include "2sysincludes.h"
#include "host_common.h"
#include "load_kernel_fw.h"
#include "secdata_tpm.h"
#include "test_common.h"
#include "tlcl.h"
#include "tss_constants.h"
#include "vboot_audio.h"
#include "vboot_common.h"
#include "vboot_kernel.h"
#include "vboot_struct.h"
#include "vboot_test.h"

/* Mock data */
static uint8_t workbuf[VB2_KERNEL_WORKBUF_RECOMMENDED_SIZE]
	__attribute__((aligned(VB2_WORKBUF_ALIGN)));
static struct vb2_context *ctx;
static struct vb2_shared_data *sd;
static VbSelectAndLoadKernelParams kparams;
static uint8_t shared_data[VB_SHARED_DATA_MIN_SIZE];
static VbSharedDataHeader *shared = (VbSharedDataHeader *)shared_data;
static struct vb2_gbb_header gbb;

static uint32_t kernel_version;
static uint32_t new_version;
static uint8_t fwmp_buf[VB2_SECDATA_FWMP_MIN_SIZE];
static uint32_t kernel_read_retval;
static uint32_t kernel_write_retval;
static uint32_t kernel_lock_retval;
static uint32_t fwmp_read_retval;
static vb2_error_t vbboot_retval;

static uint32_t mock_switches[8];
static uint32_t mock_switches_count;
static int mock_switches_are_stuck;
static int commit_data_called;

/* Reset mock data (for use before each test) */
static void ResetMocks(void)
{
	memset(&kparams, 0, sizeof(kparams));

	memset(&gbb, 0, sizeof(gbb));
	gbb.major_version = VB2_GBB_MAJOR_VER;
	gbb.minor_version = VB2_GBB_MINOR_VER;
	gbb.flags = 0;

	TEST_SUCC(vb2api_init(workbuf, sizeof(workbuf), &ctx),
		  "vb2api_init failed");
	sd = vb2_get_sd(ctx);
	sd->flags |= VB2_SD_FLAG_DISPLAY_AVAILABLE;
	ctx->flags |= VB2_CONTEXT_NO_SECDATA_FWMP;

	vb2_nv_init(ctx);
	vb2_nv_set(ctx, VB2_NV_KERNEL_MAX_ROLLFORWARD, 0xffffffff);
	commit_data_called = 0;

	memset(&shared_data, 0, sizeof(shared_data));
	VbSharedDataInit(shared, sizeof(shared_data));

	memset(&fwmp_buf, 0, sizeof(fwmp_buf));
	fwmp_read_retval = TPM_SUCCESS;

	kernel_version = new_version = 0x10002;
	kernel_read_retval = TPM_SUCCESS;
	kernel_write_retval = TPM_SUCCESS;
	kernel_lock_retval = TPM_SUCCESS;
	vbboot_retval = VB2_SUCCESS;

	memset(mock_switches, 0, sizeof(mock_switches));
	mock_switches_count = 0;
	mock_switches_are_stuck = 0;
}

/* Mock functions */

vb2_error_t vb2ex_commit_data(struct vb2_context *c)
{
	commit_data_called = 1;
	return VB2_SUCCESS;
}

uint32_t secdata_firmware_write(struct vb2_context *c)
{
	return TPM_SUCCESS;
}

uint32_t secdata_kernel_read(struct vb2_context *c)
{
	return kernel_read_retval;
}

uint32_t secdata_kernel_write(struct vb2_context *c)
{
	return kernel_write_retval;
}

uint32_t secdata_kernel_lock(struct vb2_context *c)
{
	return kernel_lock_retval;
}

uint32_t secdata_fwmp_read(struct vb2_context *c)
{
	memcpy(&c->secdata_fwmp, &fwmp_buf, sizeof(fwmp_buf));
	return fwmp_read_retval;
}

vb2_error_t vb2_secdata_firmware_init(struct vb2_context *c)
{
	return VB2_SUCCESS;
}

vb2_error_t vb2_secdata_kernel_init(struct vb2_context *c)
{
	return VB2_SUCCESS;
}

uint32_t vb2_secdata_kernel_get(struct vb2_context *c,
				enum vb2_secdata_kernel_param param)
{
	return kernel_version;
}

void vb2_secdata_kernel_set(struct vb2_context *c,
			    enum vb2_secdata_kernel_param param,
			    uint32_t value)
{
	kernel_version = value;
}

vb2_error_t VbTryLoadKernel(struct vb2_context *c, uint32_t get_info_flags)
{
	shared->kernel_version_tpm = new_version;

	if (vbboot_retval == -1)
		return VB2_ERROR_MOCK;

	return vbboot_retval;
}

vb2_error_t VbBootDeveloper(struct vb2_context *c)
{
	shared->kernel_version_tpm = new_version;

	if (vbboot_retval == -2)
		return VB2_ERROR_MOCK;

	return vbboot_retval;
}

vb2_error_t VbBootRecovery(struct vb2_context *c)
{
	shared->kernel_version_tpm = new_version;

	if (vbboot_retval == -3)
		return VB2_ERROR_MOCK;

	return vbboot_retval;
}

vb2_error_t VbBootDiagnostic(struct vb2_context *c)
{
	if (vbboot_retval == -4)
		return VB2_ERROR_MOCK;

	return vbboot_retval;
}

static void test_slk(vb2_error_t retval, int recovery_reason, const char *desc)
{
	TEST_EQ(VbSelectAndLoadKernel(ctx, shared, &kparams), retval, desc);
	TEST_EQ(vb2_nv_get(ctx, VB2_NV_RECOVERY_REQUEST),
		recovery_reason, "  recovery reason");
	if (recovery_reason)
		TEST_TRUE(commit_data_called, "  didn't commit nvdata");
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

vb2_error_t vb2ex_tpm_set_mode(enum vb2_tpm_mode mode_val)
{
	return VB2_SUCCESS;
}

/* Tests */

static void VbSlkTest(void)
{
	ResetMocks();
	test_slk(0, 0, "Normal");
	TEST_EQ(kernel_version, 0x10002, "  version");

	/*
	 * If shared->flags doesn't ask for software sync, we won't notice
	 * that error.
	 */
	ResetMocks();
	test_slk(0, 0, "EC sync not done");

	/* Same if shared->flags asks for sync, but it's overridden by GBB */
	ResetMocks();
	shared->flags |= VBSD_EC_SOFTWARE_SYNC;
	gbb.flags |= VB2_GBB_FLAG_DISABLE_EC_SOFTWARE_SYNC;
	test_slk(0, 0, "EC sync disabled by GBB");

	/* Rollback kernel version */
	ResetMocks();
	kernel_read_retval = 123;
	test_slk(VB2_ERROR_SECDATA_KERNEL_READ,
		 VB2_RECOVERY_RW_TPM_R_ERROR, "Read kernel rollback");

	ResetMocks();
	new_version = 0x20003;
	test_slk(0, 0, "Roll forward");
	TEST_EQ(kernel_version, 0x20003, "  version");

	ResetMocks();
	vb2_nv_set(ctx, VB2_NV_FW_RESULT, VB2_FW_RESULT_TRYING);
	new_version = 0x20003;
	test_slk(0, 0, "Don't roll forward kernel when trying new FW");
	TEST_EQ(kernel_version, 0x10002, "  version");

	ResetMocks();
	vb2_nv_set(ctx, VB2_NV_KERNEL_MAX_ROLLFORWARD, 0x30005);
	new_version = 0x40006;
	test_slk(0, 0, "Limit max roll forward");
	TEST_EQ(kernel_version, 0x30005, "  version");

	ResetMocks();
	vb2_nv_set(ctx, VB2_NV_KERNEL_MAX_ROLLFORWARD, 0x10001);
	new_version = 0x40006;
	test_slk(0, 0, "Max roll forward can't rollback");
	TEST_EQ(kernel_version, 0x10002, "  version");


	ResetMocks();
	new_version = 0x20003;
	kernel_write_retval = 123;
	test_slk(VB2_ERROR_SECDATA_KERNEL_WRITE,
		 VB2_RECOVERY_RW_TPM_W_ERROR, "Write kernel rollback");

	ResetMocks();
	kernel_lock_retval = 123;
	test_slk(VB2_ERROR_SECDATA_KERNEL_LOCK,
		 VB2_RECOVERY_RW_TPM_L_ERROR, "Lock kernel rollback");

	/* Boot normal */
	ResetMocks();
	vbboot_retval = -1;
	test_slk(VB2_ERROR_MOCK, 0, "Normal boot bad");

	/* Check that NV_DIAG_REQUEST triggers diagnostic UI */
	if (DIAGNOSTIC_UI) {
		ResetMocks();
		mock_switches[1] = VB_SWITCH_FLAG_PHYS_PRESENCE_PRESSED;
		vb2_nv_set(ctx, VB2_NV_DIAG_REQUEST, 1);
		vbboot_retval = -4;
		test_slk(VB2_ERROR_MOCK, 0,
			 "Normal boot with diag");
		TEST_EQ(vb2_nv_get(ctx, VB2_NV_DIAG_REQUEST),
			0, "  diag not requested");
		TEST_TRUE(commit_data_called,
			  "  didn't commit nvdata");
	}

	/* Boot dev */
	ResetMocks();
	shared->flags |= VBSD_BOOT_DEV_SWITCH_ON;
	vbboot_retval = -2;
	test_slk(VB2_ERROR_MOCK, 0, "Dev boot bad");

	ResetMocks();
	shared->flags |= VBSD_BOOT_DEV_SWITCH_ON;
	new_version = 0x20003;
	test_slk(0, 0, "Dev doesn't roll forward");
	TEST_EQ(kernel_version, 0x10002, "  version");

	/* Boot recovery */
	ResetMocks();
	shared->recovery_reason = 123;
	vbboot_retval = -3;
	test_slk(VB2_ERROR_MOCK, 0, "Recovery boot bad");

	ResetMocks();
	shared->recovery_reason = 123;
	new_version = 0x20003;
	test_slk(0, 0, "Recovery doesn't roll forward");
	TEST_EQ(kernel_version, 0x10002, "  version");

	ResetMocks();
	shared->recovery_reason = 123;
	kernel_read_retval = TPM_E_IOERROR;
	kernel_write_retval = TPM_E_IOERROR;
	kernel_lock_retval = TPM_E_IOERROR;
	test_slk(0, 0, "Recovery ignore TPM errors");

	ResetMocks();
	shared->recovery_reason = VB2_RECOVERY_TRAIN_AND_REBOOT;
	test_slk(VBERROR_REBOOT_REQUIRED, 0, "Recovery train and reboot");

	// todo: rkr/w/l fail ignored if recovery


}

int main(void)
{
	VbSlkTest();

	return gTestSuccess ? 0 : 255;
}
