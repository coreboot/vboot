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
#include "test_common.h"
#include "tlcl.h"
#include "tss_constants.h"
#include "vboot_audio.h"
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
static vb2_error_t vbboot_retval;
static vb2_error_t commit_data_retval;
static int commit_data_called;
static vb2_error_t secdata_kernel_init_retval;
static vb2_error_t secdata_fwmp_init_retval;
static vb2_error_t kernel_phase1_retval;

static uint32_t mock_switches[8];
static uint32_t mock_switches_count;
static int mock_switches_are_stuck;

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
	sd->preamble_size = 1;

	vb2_nv_init(ctx);
	vb2_nv_set(ctx, VB2_NV_KERNEL_MAX_ROLLFORWARD, 0xffffffff);
	commit_data_called = 0;

	memset(&shared_data, 0, sizeof(shared_data));

	kernel_version = new_version = 0x10002;
	commit_data_retval = VB2_SUCCESS;
	vbboot_retval = VB2_SUCCESS;
	secdata_kernel_init_retval = VB2_SUCCESS;
	secdata_fwmp_init_retval = VB2_SUCCESS;
	kernel_phase1_retval = VB2_SUCCESS;

	memset(mock_switches, 0, sizeof(mock_switches));
	mock_switches_count = 0;
	mock_switches_are_stuck = 0;
}

/* Mock functions */

struct vb2_gbb_header *vb2_get_gbb(struct vb2_context *c)
{
	return &gbb;
}

vb2_error_t vb2api_kernel_phase1(struct vb2_context *c)
{
	sd->kernel_version_secdata = kernel_version;
	shared->kernel_version_tpm_start = kernel_version;
	shared->kernel_version_tpm = kernel_version;
	return kernel_phase1_retval;
}

vb2_error_t vb2ex_commit_data(struct vb2_context *c)
{
	commit_data_called = 1;
	return commit_data_retval;
}

vb2_error_t vb2_secdata_kernel_init(struct vb2_context *c)
{
	return secdata_kernel_init_retval;
}

vb2_error_t vb2_secdata_fwmp_init(struct vb2_context *c)
{
	return secdata_fwmp_init_retval;
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

vb2_error_t VbBootDeveloperLegacyClamshell(struct vb2_context *c)
{
	shared->kernel_version_tpm = new_version;

	if (vbboot_retval == -2)
		return VB2_ERROR_MOCK;

	return vbboot_retval;
}

vb2_error_t VbBootRecoveryLegacyClamshell(struct vb2_context *c)
{
	shared->kernel_version_tpm = new_version;

	if (vbboot_retval == -3)
		return VB2_ERROR_MOCK;

	return vbboot_retval;
}

vb2_error_t VbBootDiagnosticLegacyClamshell(struct vb2_context *c)
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
	/* Normal boot */
	ResetMocks();
	test_slk(0, 0, "Normal");
	TEST_EQ(kernel_version, 0x10002, "  version");
	TEST_NEQ(sd->flags & VB2_SD_STATUS_EC_SYNC_COMPLETE, 0,
		 "  EC sync complete");

	/* Check EC sync toggling */
	ResetMocks();
	ctx->flags |= VB2_CONTEXT_EC_SYNC_SUPPORTED;
	gbb.flags |= VB2_GBB_FLAG_DISABLE_EC_SOFTWARE_SYNC;
	test_slk(0, 0, "EC sync disabled by GBB");
	TEST_NEQ(sd->flags & VB2_SD_STATUS_EC_SYNC_COMPLETE, 0,
		 "  EC sync complete");

	ResetMocks();
	ctx->flags |= VB2_CONTEXT_EC_SYNC_SUPPORTED;
	test_slk(0, 0, "Normal with EC sync");
	TEST_NEQ(sd->flags & VB2_SD_STATUS_EC_SYNC_COMPLETE, 0,
		 "  EC sync complete");

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
	commit_data_retval = VB2_ERROR_SECDATA_KERNEL_WRITE;
	test_slk(VB2_ERROR_SECDATA_KERNEL_WRITE,
		 VB2_RECOVERY_RW_TPM_W_ERROR, "Write kernel rollback");

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

	/* Boot normal - phase1 failure */
	ResetMocks();
	kernel_phase1_retval = VB2_ERROR_MOCK;
	test_slk(VB2_ERROR_MOCK, 0, "Normal phase1 failure");

	/* Boot normal - commit data failures */
	ResetMocks();
	commit_data_retval = VB2_ERROR_SECDATA_FIRMWARE_WRITE;
	test_slk(commit_data_retval, VB2_RECOVERY_RW_TPM_W_ERROR,
		 "Normal secdata_firmware write error triggers recovery");
	commit_data_retval = VB2_ERROR_SECDATA_KERNEL_WRITE;
	test_slk(commit_data_retval, VB2_RECOVERY_RW_TPM_W_ERROR,
		 "Normal secdata_kernel write error triggers recovery");
	commit_data_retval = VB2_ERROR_NV_WRITE;
	TEST_ABORT(VbSelectAndLoadKernel(ctx, shared, &kparams),
		   "Normal nvdata write error aborts");
	commit_data_retval = VB2_ERROR_UNKNOWN;
	TEST_ABORT(VbSelectAndLoadKernel(ctx, shared, &kparams),
		   "Normal unknown commit error aborts");

	/* Boot dev */
	ResetMocks();
	sd->flags |= VB2_SD_FLAG_DEV_MODE_ENABLED;
	vbboot_retval = -2;
	test_slk(VB2_ERROR_MOCK, 0, "Dev boot bad");

	ResetMocks();
	sd->flags |= VB2_SD_FLAG_DEV_MODE_ENABLED;
	new_version = 0x20003;
	test_slk(0, 0, "Dev doesn't roll forward");
	TEST_EQ(kernel_version, 0x10002, "  version");

	/* Boot dev - phase1 failure */
	ResetMocks();
	sd->flags |= VB2_SD_FLAG_DEV_MODE_ENABLED;
	kernel_phase1_retval = VB2_ERROR_MOCK;
	test_slk(VB2_ERROR_MOCK, 0, "Dev phase1 failure");

	/* Boot recovery */
	ResetMocks();
	sd->recovery_reason = 123;
	vbboot_retval = -3;
	test_slk(VB2_ERROR_MOCK, 0, "Recovery boot bad");

	ResetMocks();
	sd->recovery_reason = 123;
	new_version = 0x20003;
	test_slk(0, 0, "Recovery doesn't roll forward");
	TEST_EQ(kernel_version, 0x10002, "  version");

	/* Boot recovery - phase1 failure */
	ResetMocks();
	sd->recovery_reason = 123;
	kernel_phase1_retval = VB2_ERROR_MOCK;
	test_slk(VB2_ERROR_MOCK, 0, "Recovery phase1 failure");

	/* Boot recovery - commit data failures */
	ResetMocks();
	sd->recovery_reason = 123;
	commit_data_retval = VB2_ERROR_SECDATA_FIRMWARE_WRITE;
	test_slk(0, 0, "Recovery ignore secdata_firmware write error");
	commit_data_retval = VB2_ERROR_SECDATA_KERNEL_WRITE;
	test_slk(0, 0, "Recovery ignore secdata_kernel write error");
	commit_data_retval = VB2_ERROR_NV_WRITE;
	test_slk(0, 0, "Recovery return nvdata write error");
	commit_data_retval = VB2_ERROR_UNKNOWN;
	test_slk(0, 0, "Recovery return unknown write error");

	/* Boot recovery - nvstorage cleared */
	ResetMocks();
	sd->recovery_reason = 123;
	vb2_nv_set(ctx, VB2_NV_RECOVERY_REQUEST, 5);
	vb2_nv_set(ctx, VB2_NV_RECOVERY_SUBCODE, 13);
	test_slk(0, 0, "Recovery with nvstorage");
	TEST_EQ(vb2_nv_get(ctx, VB2_NV_RECOVERY_SUBCODE),
		0, "  recovery subcode cleared");

	/* Boot recovery - memory retraining */
	ResetMocks();
	sd->recovery_reason = VB2_RECOVERY_TRAIN_AND_REBOOT;
	test_slk(VBERROR_REBOOT_REQUIRED, 0, "Recovery train and reboot");

	// todo: rkr/w/l fail ignored if recovery


}

int main(void)
{
	VbSlkTest();

	return gTestSuccess ? 0 : 255;
}
