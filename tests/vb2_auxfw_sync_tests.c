/* Copyright 2019 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Tests for auxfw synchronization.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "2common.h"
#include "2misc.h"
#include "2nvstorage.h"
#include "2sysincludes.h"
#include "host_common.h"
#include "load_kernel_fw.h"
#include "secdata_tpm.h"
#include "test_common.h"
#include "vboot_audio.h"
#include "vboot_common.h"
#include "vboot_display.h"
#include "vboot_kernel.h"
#include "vboot_struct.h"

/* Mock data */
static uint8_t shared_data[VB_SHARED_DATA_MIN_SIZE];
static VbSharedDataHeader *shared = (VbSharedDataHeader *)shared_data;

static struct vb2_context *ctx;
static uint8_t workbuf[VB2_KERNEL_WORKBUF_RECOMMENDED_SIZE]
	__attribute__((aligned(VB2_WORKBUF_ALIGN)));
static struct vb2_shared_data *sd;
static struct vb2_gbb_header gbb;

static uint32_t screens_displayed[8];
static uint32_t screens_count = 0;

static vb2_error_t auxfw_retval;
static int auxfw_update_req;
static enum vb2_auxfw_update_severity auxfw_mock_severity;
static enum vb2_auxfw_update_severity auxfw_update_severity;
static int auxfw_protected;
static vb2_error_t auxfw_done_retval;

/* Reset mock data (for use before each test) */
static void ResetMocks(void)
{
	TEST_SUCC(vb2api_init(workbuf, sizeof(workbuf), &ctx),
		  "vb2api_init failed");

	ctx->flags = VB2_CONTEXT_EC_SYNC_SUPPORTED;
	vb2_nv_init(ctx);

	sd = vb2_get_sd(ctx);
	sd->vbsd = shared;
	sd->flags |= VB2_SD_FLAG_DISPLAY_AVAILABLE;

	memset(&gbb, 0, sizeof(gbb));

	memset(&shared_data, 0, sizeof(shared_data));
	VbSharedDataInit(shared, sizeof(shared_data));

	memset(screens_displayed, 0, sizeof(screens_displayed));
	screens_count = 0;

	auxfw_retval = VB2_SUCCESS;
	auxfw_mock_severity = VB_AUX_FW_NO_UPDATE;
	auxfw_update_severity = VB_AUX_FW_NO_UPDATE;
	auxfw_update_req = 0;
	auxfw_protected = 0;
	auxfw_done_retval = VB2_SUCCESS;
}

/* Mock functions */
struct vb2_gbb_header *vb2_get_gbb(struct vb2_context *c)
{
	return &gbb;
}

vb2_error_t VbDisplayScreen(struct vb2_context *c, uint32_t screen, int force,
			    const VbScreenData *data)
{
	if (screens_count < ARRAY_SIZE(screens_displayed))
		screens_displayed[screens_count++] = screen;

	return VB2_SUCCESS;
}

vb2_error_t vb2ex_auxfw_check(enum vb2_auxfw_update_severity *severity)
{
	*severity = auxfw_mock_severity;
	auxfw_update_severity = auxfw_mock_severity;
	return VB2_SUCCESS;
}

vb2_error_t vb2ex_auxfw_update(void)
{
	if (auxfw_update_severity != VB_AUX_FW_NO_DEVICE &&
	    auxfw_update_severity != VB_AUX_FW_NO_UPDATE)
		auxfw_update_req = 1;
	return auxfw_retval;
}

vb2_error_t vb2ex_auxfw_finalize(struct vb2_context *c)
{
	auxfw_protected = auxfw_update_severity != VB_AUX_FW_NO_DEVICE;
	return auxfw_done_retval;
}

static void test_auxsync(vb2_error_t retval, int recovery_reason,
			 const char *desc)
{
	TEST_EQ(vb2api_auxfw_sync(ctx), retval, desc);
	TEST_EQ(vb2_nv_get(ctx, VB2_NV_RECOVERY_REQUEST),
		recovery_reason, "  recovery reason");
}

/* Tests */

static void VbSoftwareSyncTest(void)
{
	ResetMocks();
	gbb.flags |= VB2_GBB_FLAG_DISABLE_EC_SOFTWARE_SYNC;
	auxfw_mock_severity = VB_AUX_FW_FAST_UPDATE;
	test_auxsync(VB2_SUCCESS, 0,
		     "VB2_GBB_FLAG_DISABLE_EC_SOFTWARE_SYNC"
		     " disables auxiliary FW update request");
	TEST_EQ(auxfw_update_req, 0, "  aux fw update disabled");
	TEST_EQ(auxfw_protected, 1, "  aux fw protected");

	ResetMocks();
	gbb.flags |= VB2_GBB_FLAG_DISABLE_AUXFW_SOFTWARE_SYNC;
	auxfw_mock_severity = VB_AUX_FW_FAST_UPDATE;
	test_auxsync(VB2_SUCCESS, 0,
		     "VB2_GBB_FLAG_DISABLE_AUXFW_SOFTWARE_SYNC"
		     " disables auxiliary FW update request");
	TEST_EQ(auxfw_update_req, 0, "  aux fw update disabled");
	TEST_EQ(auxfw_protected, 1, "  aux fw protected");

	ResetMocks();
	auxfw_mock_severity = VB_AUX_FW_NO_DEVICE;
	test_auxsync(VB2_SUCCESS, 0,
		     "No auxiliary FW update needed");
	TEST_EQ(screens_count, 0,
		"  wait screen skipped");
	TEST_EQ(auxfw_update_req, 0, "  no aux fw update requested");
	TEST_EQ(auxfw_protected, 0, "  no aux fw protected");

	ResetMocks();
	auxfw_mock_severity = VB_AUX_FW_NO_UPDATE;
	test_auxsync(VB2_SUCCESS, 0,
		"No auxiliary FW update needed");
	TEST_EQ(screens_count, 0,
		"  wait screen skipped");
	TEST_EQ(auxfw_update_req, 0, "  no aux fw update requested");
	TEST_EQ(auxfw_protected, 1, "  aux fw protected");

	ResetMocks();
	auxfw_mock_severity = VB_AUX_FW_FAST_UPDATE;
	test_auxsync(VBERROR_EC_REBOOT_TO_RO_REQUIRED, 0,
		     "Fast auxiliary FW update needed");
	TEST_EQ(screens_count, 0,
		"  wait screen skipped");
	TEST_EQ(auxfw_update_req, 1, "  aux fw update requested");
	TEST_EQ(auxfw_protected, 0, "  aux fw protected");

	ResetMocks();
	auxfw_mock_severity = VB_AUX_FW_SLOW_UPDATE;
	sd->flags &= ~VB2_SD_FLAG_DISPLAY_AVAILABLE;
	test_auxsync(VBERROR_REBOOT_REQUIRED, 0,
		     "Slow auxiliary FW update needed - reboot for display");

	ResetMocks();
	auxfw_mock_severity = VB_AUX_FW_SLOW_UPDATE;
	test_auxsync(VBERROR_EC_REBOOT_TO_RO_REQUIRED, 0,
		     "Slow auxiliary FW update needed");
	TEST_EQ(auxfw_update_req, 1, "  aux fw update requested");
	TEST_EQ(auxfw_protected, 0, "  aux fw protected");
	TEST_EQ(screens_displayed[0], VB_SCREEN_WAIT,
		"  wait screen forced");

	ResetMocks();
	auxfw_mock_severity = VB_AUX_FW_FAST_UPDATE;
	auxfw_retval = VB2_ERROR_UNKNOWN;
	test_auxsync(VB2_ERROR_UNKNOWN, VB2_RECOVERY_AUX_FW_UPDATE,
		     "Error updating AUX firmware");
}

int main(void)
{
	VbSoftwareSyncTest();

	return gTestSuccess ? 0 : 255;
}
