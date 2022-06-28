/* Copyright (c) 2013 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Tests for VbTryLoadKernel()
 */

#include "2common.h"
#include "2misc.h"
#include "2nvstorage.h"
#include "2sysincludes.h"
#include "load_kernel_fw.h"
#include "test_common.h"
#include "vboot_api.h"

#define MAX_TEST_DISKS 10
#define DEFAULT_COUNT -1

typedef struct {
	uint64_t bytes_per_lba;
	uint64_t lba_count;
	uint32_t flags;
	const char *diskname;
} disk_desc_t;

typedef struct {
	const char *name;

	/* inputs for test case */
	uint32_t ctx_flags;
	uint32_t want_flags;
	vb2_error_t diskgetinfo_return_val;
	disk_desc_t disks_to_provide[MAX_TEST_DISKS];
	int disk_count_to_return;
	vb2_error_t loadkernel_return_val[MAX_TEST_DISKS];
	uint8_t external_expected[MAX_TEST_DISKS];

	/* outputs from test */
	uint32_t expected_recovery_request_val;
	const char *expected_to_find_disk;
	const char *expected_to_load_disk;
	uint32_t expected_return_val;

} test_case_t;

/****************************************************************************/
/* Test cases */

static const char pickme[] = "correct choice";
#define DONT_CARE ((const char *)42)

test_case_t normal_tests[] = {
	{
		.name = "first drive (removable)",
		.ctx_flags = 0,
		.want_flags = VB_DISK_FLAG_REMOVABLE | VB_DISK_FLAG_FIXED,
		.disks_to_provide = {
			{4096, 100, VB_DISK_FLAG_REMOVABLE, pickme},
			{4096, 100, VB_DISK_FLAG_FIXED, "holygrail"},
		},
		.disk_count_to_return = DEFAULT_COUNT,
		.diskgetinfo_return_val = VB2_SUCCESS,
		.loadkernel_return_val = {0},
		.external_expected = {0},

		.expected_recovery_request_val = VB2_RECOVERY_NOT_REQUESTED,
		.expected_to_find_disk = pickme,
		.expected_to_load_disk = pickme,
		.expected_return_val = VB2_SUCCESS
	},
	{
		.name = "first drive (fixed)",
		.ctx_flags = 0,
		.want_flags = VB_DISK_FLAG_REMOVABLE | VB_DISK_FLAG_FIXED,
		.disks_to_provide = {
			{4096, 100, VB_DISK_FLAG_FIXED, pickme},
			{4096, 100, VB_DISK_FLAG_REMOVABLE, "holygrail"},
		},
		.disk_count_to_return = DEFAULT_COUNT,
		.diskgetinfo_return_val = VB2_SUCCESS,
		.loadkernel_return_val = {0},
		.external_expected = {0},

		.expected_recovery_request_val = VB2_RECOVERY_NOT_REQUESTED,
		.expected_to_find_disk = pickme,
		.expected_to_load_disk = pickme,
		.expected_return_val = VB2_SUCCESS
	},
	{
		.name = "first removable drive",
		.ctx_flags = 0,
		.want_flags = VB_DISK_FLAG_REMOVABLE,
		.disks_to_provide = {
			/* too small */
			{512,  10,   VB_DISK_FLAG_REMOVABLE, 0},
			/* wrong LBA */
			{511, 100,  VB_DISK_FLAG_REMOVABLE, 0},
			/* not a power of 2 */
			{2047, 100,  VB_DISK_FLAG_REMOVABLE, 0},
			/* wrong type */
			{512,  100,  VB_DISK_FLAG_FIXED, 0},
			/* wrong flags */
			{512,  100,  0, 0},
			/* still wrong flags */
			{512,  100,  -1, 0},
			{4096, 100,  VB_DISK_FLAG_REMOVABLE, pickme},
			/* already got one */
			{512,  100,  VB_DISK_FLAG_REMOVABLE, "holygrail"},
		},
		.disk_count_to_return = DEFAULT_COUNT,
		.diskgetinfo_return_val = VB2_SUCCESS,
		.loadkernel_return_val = {0},
		.external_expected = {0},

		.expected_recovery_request_val = VB2_RECOVERY_NOT_REQUESTED,
		.expected_to_find_disk = pickme,
		.expected_to_load_disk = pickme,
		.expected_return_val = VB2_SUCCESS
	},
	{
		.name = "first removable drive (skip external GPT)",
		.ctx_flags = 0,
		.want_flags = VB_DISK_FLAG_REMOVABLE,
		.disks_to_provide = {
			/* too small */
			{512,  10,   VB_DISK_FLAG_REMOVABLE, 0},
			/* wrong LBA */
			{511, 100,  VB_DISK_FLAG_REMOVABLE, 0},
			/* not a power of 2 */
			{2047, 100,  VB_DISK_FLAG_REMOVABLE, 0},
			/* wrong type */
			{512,  100,  VB_DISK_FLAG_FIXED, 0},
			/* wrong flags */
			{512,  100,  0, 0},
			/* still wrong flags */
			{512,  100,  -1, 0},
			{512,  100,
			 VB_DISK_FLAG_REMOVABLE | VB_DISK_FLAG_EXTERNAL_GPT,
			 pickme},
			/* already got one */
			{512,  100,  VB_DISK_FLAG_REMOVABLE, "holygrail"},
		},
		.disk_count_to_return = DEFAULT_COUNT,
		.diskgetinfo_return_val = VB2_SUCCESS,
		.loadkernel_return_val = {0, 0},
		.external_expected = {1, 0},

		.expected_recovery_request_val = VB2_RECOVERY_NOT_REQUESTED,
		.expected_to_find_disk = pickme,
		.expected_to_load_disk = pickme,
		.expected_return_val = VB2_SUCCESS
	},
	{
		.name = "second removable drive",
		.ctx_flags = 0,
		.want_flags = VB_DISK_FLAG_REMOVABLE,
		.disks_to_provide = {
			/* wrong flags */
			{512,  100,  0, 0},
			{512,  100,  VB_DISK_FLAG_REMOVABLE, "not yet"},
			{512,  100,  VB_DISK_FLAG_REMOVABLE, pickme},
		},
		.disk_count_to_return = DEFAULT_COUNT,
		.diskgetinfo_return_val = VB2_SUCCESS,
		.loadkernel_return_val = {VB2_ERROR_LK_INVALID_KERNEL_FOUND, 0},

		.expected_recovery_request_val = VB2_RECOVERY_NOT_REQUESTED,
		.expected_to_find_disk = pickme,
		.expected_to_load_disk = pickme,
		.expected_return_val = VB2_SUCCESS
	},
	{
		.name = "first fixed drive",
		.ctx_flags = 0,
		.want_flags = VB_DISK_FLAG_FIXED,
		.disks_to_provide = {
			/* too small */
			{512,   10,  VB_DISK_FLAG_FIXED, 0},
			/* wrong LBA */
			{511, 100,  VB_DISK_FLAG_FIXED, 0},
			/* not a power of 2 */
			{2047, 100,  VB_DISK_FLAG_REMOVABLE, 0},
			/* wrong type */
			{512,  100,  VB_DISK_FLAG_REMOVABLE, 0},
			/* wrong flags */
			{512,  100,  0, 0},
			/* still wrong flags */
			{512,  100,  -1, 0},
			/* flags */
			{512,  100,  VB_DISK_FLAG_REMOVABLE|VB_DISK_FLAG_FIXED,
			 0},
			{512,  100,  VB_DISK_FLAG_FIXED, pickme},
			/* already got one */
			{512,  100,  VB_DISK_FLAG_FIXED, "holygrail"},
		},
		.disk_count_to_return = DEFAULT_COUNT,
		.diskgetinfo_return_val = VB2_SUCCESS,
		.loadkernel_return_val = {0},

		.expected_recovery_request_val = VB2_RECOVERY_NOT_REQUESTED,
		.expected_to_find_disk = pickme,
		.expected_to_load_disk = pickme,
		.expected_return_val = VB2_SUCCESS
	},
	{
		.name = "no drives at all",
		.ctx_flags = 0,
		.want_flags = VB_DISK_FLAG_FIXED,
		.disks_to_provide = {},
		.disk_count_to_return = DEFAULT_COUNT,
		.diskgetinfo_return_val = VB2_SUCCESS,

		.expected_recovery_request_val = VB2_RECOVERY_RW_NO_DISK,
		.expected_to_find_disk = 0,
		.expected_to_load_disk = 0,
		.expected_return_val = VB2_ERROR_LK_NO_DISK_FOUND
	},
	{
		.name = "VbExDiskGetInfo() error",
		.ctx_flags = 0,
		.want_flags = VB_DISK_FLAG_FIXED,
		.disks_to_provide = {
			{512,  10, VB_DISK_FLAG_REMOVABLE, 0},
			{512, 100, VB_DISK_FLAG_FIXED, 0},
		},
		.disk_count_to_return = DEFAULT_COUNT,
		.diskgetinfo_return_val = VB2_ERROR_UNKNOWN,

		.expected_recovery_request_val = VB2_RECOVERY_RW_NO_DISK,
		.expected_to_find_disk = 0,
		.expected_to_load_disk = 0,
		.expected_return_val = VB2_ERROR_LK_NO_DISK_FOUND,
	},
	{
		.name = "invalid kernel",
		.ctx_flags = 0,
		.want_flags = VB_DISK_FLAG_FIXED,
		.disks_to_provide = {
			/* too small */
			{512,   10,  VB_DISK_FLAG_FIXED, 0},
			/* wrong LBA */
			{511, 100,  VB_DISK_FLAG_FIXED, 0},
			/* not a power of 2 */
			{2047, 100,  VB_DISK_FLAG_FIXED, 0},
			/* wrong type */
			{512,  100,  VB_DISK_FLAG_REMOVABLE, 0},
			/* wrong flags */
			{512,  100,  0, 0},
			/* still wrong flags */
			{512,  100,  -1, 0},
			/* doesn't load */
			{512,  100,  VB_DISK_FLAG_FIXED, "corrupted kernel"},
			/* doesn't load */
			{512,  100,  VB_DISK_FLAG_FIXED, "stateful partition"},
		},
		.disk_count_to_return = DEFAULT_COUNT,
		.diskgetinfo_return_val = VB2_SUCCESS,
		.loadkernel_return_val = {VB2_ERROR_LK_INVALID_KERNEL_FOUND,
					  VB2_ERROR_LK_NO_KERNEL_FOUND},

		.expected_recovery_request_val = VB2_RECOVERY_RW_INVALID_OS,
		.expected_to_find_disk = DONT_CARE,
		.expected_to_load_disk = 0,
		.expected_return_val = VB2_ERROR_LK_INVALID_KERNEL_FOUND,
	},
	{
		.name = "invalid kernel, order flipped",
		.ctx_flags = 0,
		.want_flags = VB_DISK_FLAG_FIXED,
		.disks_to_provide = {
			{512, 1000, VB_DISK_FLAG_FIXED, "stateful partition"},
			{512, 1000, VB_DISK_FLAG_FIXED, "corrupted kernel"},
		},
		.disk_count_to_return = DEFAULT_COUNT,
		.diskgetinfo_return_val = VB2_SUCCESS,
		.loadkernel_return_val = {VB2_ERROR_LK_NO_KERNEL_FOUND,
					  VB2_ERROR_LK_INVALID_KERNEL_FOUND},

		.expected_recovery_request_val = VB2_RECOVERY_RW_INVALID_OS,
		.expected_to_find_disk = DONT_CARE,
		.expected_to_load_disk = 0,
		.expected_return_val = VB2_ERROR_LK_INVALID_KERNEL_FOUND,
	},
	{
		.name = "no Chrome OS partitions",
		.ctx_flags = 0,
		.want_flags = VB_DISK_FLAG_FIXED,
		.disks_to_provide = {
			{512, 100, VB_DISK_FLAG_FIXED, "stateful partition"},
			{512, 1000, VB_DISK_FLAG_FIXED, "Chrubuntu"},
		},
		.disk_count_to_return = DEFAULT_COUNT,
		.diskgetinfo_return_val = VB2_SUCCESS,
		.loadkernel_return_val = {VB2_ERROR_LK_NO_KERNEL_FOUND,
					  VB2_ERROR_LK_NO_KERNEL_FOUND},

		.expected_recovery_request_val = VB2_RECOVERY_RW_NO_KERNEL,
		.expected_to_find_disk = DONT_CARE,
		.expected_to_load_disk = 0,
		.expected_return_val = VB2_ERROR_LK_NO_KERNEL_FOUND,
	},
	{
		.name = "invalid kernel (removable)",
		.ctx_flags = 0,
		.want_flags = VB_DISK_FLAG_REMOVABLE,
		.disks_to_provide = {
			{512,  100,  VB_DISK_FLAG_REMOVABLE, "corrupted"},
			{512,  100,  VB_DISK_FLAG_REMOVABLE, "data"},
		},
		.disk_count_to_return = DEFAULT_COUNT,
		.diskgetinfo_return_val = VB2_SUCCESS,
		.loadkernel_return_val = {VB2_ERROR_LK_INVALID_KERNEL_FOUND,
					  VB2_ERROR_LK_NO_KERNEL_FOUND},

		.expected_recovery_request_val = VB2_RECOVERY_RW_INVALID_OS,
		.expected_to_find_disk = DONT_CARE,
		.expected_to_load_disk = 0,
		.expected_return_val = VB2_ERROR_LK_INVALID_KERNEL_FOUND,
	},
	{
		.name = "invalid kernel (removable, rec mode)",
		.ctx_flags = VB2_CONTEXT_RECOVERY_MODE,
		.want_flags = VB_DISK_FLAG_REMOVABLE,
		.disks_to_provide = {
			{512,  100,  VB_DISK_FLAG_REMOVABLE, "corrupted"},
			{512,  100,  VB_DISK_FLAG_REMOVABLE, "data"},
		},
		.disk_count_to_return = DEFAULT_COUNT,
		.diskgetinfo_return_val = VB2_SUCCESS,
		.loadkernel_return_val = {VB2_ERROR_LK_INVALID_KERNEL_FOUND,
					  VB2_ERROR_LK_NO_KERNEL_FOUND},

		.expected_recovery_request_val = VB2_RECOVERY_NOT_REQUESTED,
		.expected_to_find_disk = DONT_CARE,
		.expected_to_load_disk = 0,
		.expected_return_val = VB2_ERROR_LK_INVALID_KERNEL_FOUND,
	},
	{
		.name = "invalid kernel (removable, dev mode)",
		.ctx_flags = VB2_CONTEXT_DEVELOPER_MODE,
		.want_flags = VB_DISK_FLAG_REMOVABLE,
		.disks_to_provide = {
			{512,  100,  VB_DISK_FLAG_REMOVABLE, "corrupted"},
			{512,  100,  VB_DISK_FLAG_REMOVABLE, "data"},
		},
		.disk_count_to_return = DEFAULT_COUNT,
		.diskgetinfo_return_val = VB2_SUCCESS,
		.loadkernel_return_val = {VB2_ERROR_LK_INVALID_KERNEL_FOUND,
					  VB2_ERROR_LK_NO_KERNEL_FOUND},

		.expected_recovery_request_val = VB2_RECOVERY_NOT_REQUESTED,
		.expected_to_find_disk = DONT_CARE,
		.expected_to_load_disk = 0,
		.expected_return_val = VB2_ERROR_LK_INVALID_KERNEL_FOUND,
	},
	{
		.name = "no kernel (removable)",
		.ctx_flags = 0,
		.want_flags = VB_DISK_FLAG_REMOVABLE,
		.disks_to_provide = {
			{512,  100,  VB_DISK_FLAG_REMOVABLE, "data"},
		},
		.disk_count_to_return = DEFAULT_COUNT,
		.diskgetinfo_return_val = VB2_SUCCESS,
		.loadkernel_return_val = {VB2_ERROR_LK_NO_KERNEL_FOUND},

		.expected_recovery_request_val = VB2_RECOVERY_RW_NO_KERNEL,
		.expected_to_find_disk = DONT_CARE,
		.expected_to_load_disk = 0,
		.expected_return_val = VB2_ERROR_LK_NO_KERNEL_FOUND,
	},
	{
		.name = "no kernel (removable, rec mode)",
		.ctx_flags = VB2_CONTEXT_RECOVERY_MODE,
		.want_flags = VB_DISK_FLAG_REMOVABLE,
		.disks_to_provide = {
			{512,  100,  VB_DISK_FLAG_REMOVABLE, "data"},
		},
		.disk_count_to_return = DEFAULT_COUNT,
		.diskgetinfo_return_val = VB2_SUCCESS,
		.loadkernel_return_val = {VB2_ERROR_LK_NO_KERNEL_FOUND},

		.expected_recovery_request_val = VB2_RECOVERY_NOT_REQUESTED,
		.expected_to_find_disk = DONT_CARE,
		.expected_to_load_disk = 0,
		.expected_return_val = VB2_ERROR_LK_NO_KERNEL_FOUND,
	},
};

test_case_t minios_tests[] = {
	{
		.name = "pick first fixed drive",
		.ctx_flags = 0,
		.disks_to_provide = {
			{4096, 100, VB_DISK_FLAG_REMOVABLE, 0},
			{4096, 100, VB_DISK_FLAG_FIXED, pickme},
			{4096, 100, VB_DISK_FLAG_FIXED, "holygrail"},
		},
		.disk_count_to_return = DEFAULT_COUNT,
		.diskgetinfo_return_val = VB2_SUCCESS,
		.loadkernel_return_val = {0},
		.external_expected = {0},

		.expected_recovery_request_val = VB2_RECOVERY_NOT_REQUESTED,
		.expected_to_find_disk = pickme,
		.expected_to_load_disk = pickme,
		.expected_return_val = VB2_SUCCESS
	},
	{
		.name = "skip failed fixed drive",
		.ctx_flags = 0,
		.disks_to_provide = {
			{4096, 100, VB_DISK_FLAG_FIXED, "holygrail"},
			{4096, 100, VB_DISK_FLAG_FIXED, pickme},
		},
		.disk_count_to_return = DEFAULT_COUNT,
		.diskgetinfo_return_val = VB2_SUCCESS,
		.loadkernel_return_val = {VB2_ERROR_LK_INVALID_KERNEL_FOUND, 0},
		.external_expected = {0},

		.expected_recovery_request_val = VB2_RECOVERY_NOT_REQUESTED,
		.expected_to_find_disk = pickme,
		.expected_to_load_disk = pickme,
		.expected_return_val = VB2_SUCCESS
	},
};

/****************************************************************************/

/* Mock data */
static VbDiskInfo mock_disks[MAX_TEST_DISKS];
static test_case_t *t;
static int load_kernel_calls;
static int lk_normal_calls;
static int lk_minios_calls;
static uint32_t got_recovery_request_val;
static const char *got_find_disk;
static const char *got_load_disk;
static uint32_t got_return_val;
static uint32_t got_external_mismatch;
static uint8_t workbuf[VB2_KERNEL_WORKBUF_RECOMMENDED_SIZE]
	__attribute__((aligned(VB2_WORKBUF_ALIGN)));
static struct vb2_context *ctx;
static struct VbSelectAndLoadKernelParams kparams;

/**
 * Reset mock data (for use before each test)
 */
static void ResetMocks(test_case_t *test_case)
{
	TEST_SUCC(vb2api_init(workbuf, sizeof(workbuf), &ctx),
		  "vb2api_init failed");

	memset(&kparams, 0, sizeof(kparams));


	memset(&mock_disks, 0, sizeof(mock_disks));
	load_kernel_calls = 0;
	lk_normal_calls = 0;
	lk_minios_calls = 0;

	got_recovery_request_val = VB2_RECOVERY_NOT_REQUESTED;
	got_find_disk = 0;
	got_load_disk = 0;
	got_return_val = 0xdeadbeef;

	t = test_case;
}

static int is_nonzero(const void *vptr, size_t count)
{
	const char *p = (const char *)vptr;
	while (count--)
		if (*p++)
			return 1;

	return 0;
}

/****************************************************************************/
/* Mocked verification functions */

vb2_error_t VbExDiskGetInfo(VbDiskInfo **infos_ptr, uint32_t *count,
			    uint32_t disk_flags)
{
	int i;
	int num_disks = 0;

	VB2_DEBUG("My %s\n", __FUNCTION__);

	*infos_ptr = mock_disks;

	for(i = 0; i < MAX_TEST_DISKS; i++) {
		if (is_nonzero(&t->disks_to_provide[i],
			       sizeof(t->disks_to_provide[i]))) {
			mock_disks[num_disks].bytes_per_lba =
				t->disks_to_provide[i].bytes_per_lba;
			mock_disks[num_disks].lba_count =
				mock_disks[num_disks].streaming_lba_count =
				t->disks_to_provide[i].lba_count;
			mock_disks[num_disks].flags =
				t->disks_to_provide[i].flags;
			mock_disks[num_disks].handle = (VbExDiskHandle_t)
				t->disks_to_provide[i].diskname;
			VB2_DEBUG("  mock_disk[%d] %" PRIu64 " %" PRIu64
				  " %#x %s\n", i,
				  mock_disks[num_disks].bytes_per_lba,
				  mock_disks[num_disks].lba_count,
				  mock_disks[num_disks].flags,
				  (mock_disks[num_disks].handle
				   ? (char *)mock_disks[num_disks].handle
				   : "0"));
			num_disks++;
		} else {
			mock_disks[num_disks].handle =
				(VbExDiskHandle_t)"INVALID";
		}
	}

	if (t->disk_count_to_return >= 0)
		*count = t->disk_count_to_return;
	else
		*count = num_disks;

	VB2_DEBUG("  *count=%" PRIu32 "\n", *count);
	VB2_DEBUG("  return %#x\n", t->diskgetinfo_return_val);

	return t->diskgetinfo_return_val;
}

vb2_error_t VbExDiskFreeInfo(VbDiskInfo *infos,
			   VbExDiskHandle_t preserve_handle)
{
	got_load_disk = (const char *)preserve_handle;
	VB2_DEBUG("%s(): got_load_disk = %s\n", __FUNCTION__,
		  got_load_disk ? got_load_disk : "0");
	return VB2_SUCCESS;
}

static vb2_error_t LoadKernelImpl(struct vb2_context *c,
				  VbSelectAndLoadKernelParams *params,
				  VbDiskInfo *disk_info)
{
	got_find_disk = (const char *)params->disk_handle;
	VB2_DEBUG("%s(%d): got_find_disk = %s\n", __FUNCTION__,
		  load_kernel_calls,
		  got_find_disk ? got_find_disk : "0");
	if (t->external_expected[load_kernel_calls] !=
			!!(disk_info->flags & VB_DISK_FLAG_EXTERNAL_GPT))
		got_external_mismatch++;
	return t->loadkernel_return_val[load_kernel_calls++];
}

vb2_error_t LoadKernel(struct vb2_context *c,
		       VbSelectAndLoadKernelParams *params,
		       VbDiskInfo *disk_info)
{
	lk_normal_calls++;
	return LoadKernelImpl(c, params, disk_info);
}

vb2_error_t LoadMiniOsKernel(struct vb2_context *c,
			     VbSelectAndLoadKernelParams *params,
			     VbDiskInfo *disk_info, uint32_t minios_flags)
{
	lk_minios_calls++;
	return LoadKernelImpl(c, params, disk_info);
}

void vb2_nv_set(struct vb2_context *c,
		enum vb2_nv_param param,
		uint32_t value)
{
	if (param != VB2_NV_RECOVERY_REQUEST)
		return;
	VB2_DEBUG("%s(): got_recovery_request_val = %d (%#x)\n", __FUNCTION__,
		  value, value);
	got_recovery_request_val = value;
}

/****************************************************************************/

static void VbTryLoadKernelTest(void)
{
	int i;
	int num_tests = ARRAY_SIZE(normal_tests);

	for (i = 0; i < num_tests; i++) {
		printf("Test case: %s ...\n", normal_tests[i].name);
		ResetMocks(&normal_tests[i]);
		ctx->flags = t->ctx_flags;
		TEST_EQ(VbTryLoadKernel(ctx, t->want_flags, &kparams),
			t->expected_return_val, "  return value");
		TEST_EQ(got_recovery_request_val,
			t->expected_recovery_request_val, "  recovery_request");
		if (t->expected_to_find_disk != DONT_CARE) {
			TEST_PTR_EQ(got_find_disk, t->expected_to_find_disk,
				    "  find disk");
			TEST_PTR_EQ(got_load_disk, t->expected_to_load_disk,
				    "  load disk");
		}
		TEST_EQ(got_external_mismatch, 0, "  external GPT errors");
		TEST_EQ(!!(ctx->flags & VB2_CONTEXT_DISABLE_TPM), 0,
			"  ctx flag disable_tpm");
	}
	TEST_EQ(lk_normal_calls, load_kernel_calls, "  LoadKernel called");
	TEST_EQ(lk_minios_calls, 0, "  LoadMiniOsKernel not called");
}

static void VbTryLoadMiniOsKernelTest(void)
{
	int i;
	int num_tests =  ARRAY_SIZE(minios_tests);

	for (i = 0; i < num_tests; i++) {
		printf("Test case: %s ...\n", minios_tests[i].name);
		ResetMocks(&minios_tests[i]);
		ctx->flags = t->ctx_flags;
		TEST_EQ(VbTryLoadMiniOsKernel(ctx, 0, &kparams),
			t->expected_return_val, "  return value");
		TEST_EQ(got_recovery_request_val,
			t->expected_recovery_request_val, "  recovery_request");
		if (t->expected_to_find_disk != DONT_CARE) {
			TEST_PTR_EQ(got_find_disk, t->expected_to_find_disk,
				    "  find disk");
			TEST_PTR_EQ(got_load_disk, t->expected_to_load_disk,
				    "  load disk");
		}
		TEST_EQ(got_external_mismatch, 0, "  external GPT errors");
		TEST_EQ(!!(ctx->flags & VB2_CONTEXT_DISABLE_TPM), 1,
			"  ctx flag disable_tpm");
	}
	TEST_EQ(lk_normal_calls, 0, "  LoadKernel not called");
	TEST_EQ(lk_minios_calls, load_kernel_calls,
		"  LoadMiniOsKernel called");
}

int main(void)
{
	VbTryLoadKernelTest();
	VbTryLoadMiniOsKernelTest();

	return gTestSuccess ? 0 : 255;
}
