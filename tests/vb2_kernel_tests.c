/* Copyright 2020 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Tests for kernel selection, loading, verification, and booting.
 */

#include "2api.h"
#include "2common.h"
#include "2misc.h"
#include "2nvstorage.h"
#include "2rsa.h"
#include "2secdata.h"
#include "2sysincludes.h"
#include "test_common.h"
#include "vb2_common.h"
#include "vboot_struct.h"

/* Common context for tests */
static uint8_t workbuf[VB2_KERNEL_WORKBUF_RECOMMENDED_SIZE]
	__attribute__((aligned(VB2_WORKBUF_ALIGN)));
static struct vb2_context *ctx;
static struct vb2_shared_data *sd;
static struct vb2_fw_preamble *fwpre;
static const char fw_kernel_key_data[36] = "Test kernel key data";

/* Mocked function data */

static struct {
	struct vb2_gbb_header h;
	struct vb2_packed_key recovery_key;
	char recovery_key_data[32];
} mock_gbb;

static int mock_read_res_fail_on_call;
static int mock_secdata_fwmp_check_retval;

/* Type of test to reset for */
enum reset_type {
	FOR_PHASE1,
};

static void reset_common_data(enum reset_type t)
{
	struct vb2_packed_key *k;

	memset(workbuf, 0xaa, sizeof(workbuf));

	TEST_SUCC(vb2api_init(workbuf, sizeof(workbuf), &ctx),
		  "vb2api_init failed");

	sd = vb2_get_sd(ctx);
	vb2_nv_init(ctx);

	vb2api_secdata_kernel_create(ctx);
	vb2_secdata_kernel_init(ctx);
	vb2_secdata_kernel_set(ctx, VB2_SECDATA_KERNEL_VERSIONS, 0x20002);

	mock_read_res_fail_on_call = 0;
	mock_secdata_fwmp_check_retval = VB2_SUCCESS;

	/* Recovery key in mock GBB */
	memset(&mock_gbb, 0, sizeof(mock_gbb));
	mock_gbb.recovery_key.algorithm = 11;
	mock_gbb.recovery_key.key_offset =
		vb2_offset_of(&mock_gbb.recovery_key,
			      &mock_gbb.recovery_key_data);
	mock_gbb.recovery_key.key_size = sizeof(mock_gbb.recovery_key_data);
	strcpy(mock_gbb.recovery_key_data, "The recovery key");
	mock_gbb.h.recovery_key_offset =
		vb2_offset_of(&mock_gbb, &mock_gbb.recovery_key);
	mock_gbb.h.recovery_key_size =
		mock_gbb.recovery_key.key_offset +
		mock_gbb.recovery_key.key_size;


	if (t == FOR_PHASE1) {
		uint8_t *kdata;

		/* Create mock firmware preamble in the context */
		sd->preamble_offset = sd->workbuf_used;
		fwpre = (struct vb2_fw_preamble *)
			vb2_member_of(sd, sd->preamble_offset);
		k = &fwpre->kernel_subkey;
		kdata = (uint8_t *)fwpre + sizeof(*fwpre);
		memcpy(kdata, fw_kernel_key_data, sizeof(fw_kernel_key_data));
		k->algorithm = 7;
		k->key_offset = vb2_offset_of(k, kdata);
		k->key_size = sizeof(fw_kernel_key_data);
		sd->preamble_size = sizeof(*fwpre) + k->key_size;
		vb2_set_workbuf_used(ctx, 
				     sd->preamble_offset + sd->preamble_size);

		/* Needed to check that secdata_kernel initialization is
		   performed by phase1 function. */
		sd->status &= ~VB2_SD_STATUS_SECDATA_KERNEL_INIT;

	}
};

/* Mocked functions */

vb2_error_t vb2api_secdata_fwmp_check(struct vb2_context *c, uint8_t *size)
{
	return mock_secdata_fwmp_check_retval;
}

struct vb2_gbb_header *vb2_get_gbb(struct vb2_context *c)
{
	return &mock_gbb.h;
}

vb2_error_t vb2ex_read_resource(struct vb2_context *c,
				enum vb2_resource_index index, uint32_t offset,
				void *buf, uint32_t size)
{
	uint8_t *rptr;
	uint32_t rsize;

	if (--mock_read_res_fail_on_call == 0)
		return VB2_ERROR_MOCK;

	switch(index) {
	case VB2_RES_GBB:
		rptr = (uint8_t *)&mock_gbb;
		rsize = sizeof(mock_gbb);
		break;
	default:
		return VB2_ERROR_EX_READ_RESOURCE_INDEX;
	}

	if (offset > rsize || offset + size > rsize)
		return VB2_ERROR_EX_READ_RESOURCE_SIZE;

	memcpy(buf, rptr + offset, size);
	return VB2_SUCCESS;
}

/* Tests */

static void phase1_tests(void)
{
	struct vb2_packed_key *k;
	uint32_t wb_used_before;

	/* Test successful call */
	reset_common_data(FOR_PHASE1);
	TEST_SUCC(vb2api_kernel_phase1(ctx), "phase1 good");
	/* Make sure normal key was loaded */
	TEST_EQ(sd->kernel_key_offset, sd->preamble_offset +
		offsetof(struct vb2_fw_preamble, kernel_subkey),
		"  workbuf key offset");
	k = vb2_member_of(sd, sd->kernel_key_offset);
	TEST_EQ(sd->kernel_key_size, k->key_offset + k->key_size,
		"  workbuf key size");
	TEST_EQ(sd->workbuf_used,
		vb2_wb_round_up(sd->kernel_key_offset +
				sd->kernel_key_size),
		"  workbuf used");
	TEST_EQ(k->algorithm, 7, "  key algorithm");
	TEST_EQ(k->key_size, sizeof(fw_kernel_key_data), "  key_size");
	TEST_EQ(memcmp((uint8_t *)k + k->key_offset, fw_kernel_key_data,
		       k->key_size), 0, "  key data");
	TEST_EQ(sd->kernel_version_secdata, 0x20002,
		"  secdata_kernel version");

	/* Test successful call in recovery mode */
	reset_common_data(FOR_PHASE1);
	ctx->flags |= VB2_CONTEXT_RECOVERY_MODE;
	/* No preamble needed in recovery mode */
	sd->workbuf_used = sd->preamble_offset;
	sd->preamble_offset = sd->preamble_size = 0;
	wb_used_before = sd->workbuf_used;
	TEST_SUCC(vb2api_kernel_phase1(ctx), "phase1 rec good");
	/* Make sure recovery key was loaded */
	TEST_EQ(sd->kernel_key_offset, wb_used_before,
		"  workbuf key offset");
	k = vb2_member_of(sd, sd->kernel_key_offset);
	TEST_EQ(sd->kernel_key_size, k->key_offset + k->key_size,
		"  workbuf key size");
	TEST_EQ(sd->workbuf_used,
		vb2_wb_round_up(sd->kernel_key_offset +
				sd->kernel_key_size),
		"  workbuf used");
	TEST_EQ(k->algorithm, 11, "  key algorithm");
	TEST_EQ(k->key_size, sizeof(mock_gbb.recovery_key_data), "  key_size");
	TEST_EQ(memcmp((uint8_t *)k + k->key_offset,
		       mock_gbb.recovery_key_data, k->key_size), 0,
		"  key data");
	TEST_EQ(sd->kernel_version_secdata, 0x20002,
		"  secdata_kernel version");

	/* Bad secdata_kernel causes failure in normal mode only */
	reset_common_data(FOR_PHASE1);
	ctx->secdata_kernel[2] ^= 0x33;  /* 3rd byte is CRC */
	TEST_EQ(vb2api_kernel_phase1(ctx), VB2_ERROR_SECDATA_KERNEL_CRC,
		"phase1 bad secdata_kernel");
	TEST_EQ(vb2_nv_get(ctx, VB2_NV_RECOVERY_REQUEST),
		VB2_RECOVERY_SECDATA_KERNEL_INIT, "  recovery reason");

	reset_common_data(FOR_PHASE1);
	ctx->secdata_kernel[0] ^= 0x33;
	ctx->flags |= VB2_CONTEXT_RECOVERY_MODE;
	TEST_SUCC(vb2api_kernel_phase1(ctx), "phase1 bad secdata_kernel rec");
	TEST_EQ(sd->kernel_version_secdata, 0, "  secdata_kernel version");
	TEST_EQ(vb2_nv_get(ctx, VB2_NV_RECOVERY_REQUEST),
		VB2_RECOVERY_NOT_REQUESTED, "  no recovery");

	/* Bad secdata_fwmp causes failure in normal mode only */
	reset_common_data(FOR_PHASE1);
	mock_secdata_fwmp_check_retval = VB2_ERROR_SECDATA_FWMP_CRC;
	TEST_EQ(vb2api_kernel_phase1(ctx), mock_secdata_fwmp_check_retval,
		"phase1 bad secdata_fwmp");
	TEST_EQ(vb2_nv_get(ctx, VB2_NV_RECOVERY_REQUEST),
		VB2_RECOVERY_SECDATA_FWMP_INIT, "  recovery reason");

	reset_common_data(FOR_PHASE1);
	mock_secdata_fwmp_check_retval = VB2_ERROR_SECDATA_FWMP_CRC;
	ctx->flags |= VB2_CONTEXT_RECOVERY_MODE;
	TEST_SUCC(vb2api_kernel_phase1(ctx), "phase1 bad secdata_fwmp rec");
	TEST_EQ(vb2_nv_get(ctx, VB2_NV_RECOVERY_REQUEST),
		VB2_RECOVERY_NOT_REQUESTED, "  no recovery");

	/* Failures while reading recovery key */
	reset_common_data(FOR_PHASE1);
	ctx->flags |= VB2_CONTEXT_RECOVERY_MODE;
	mock_gbb.h.recovery_key_size = sd->workbuf_size - 1;
	mock_gbb.recovery_key.key_size =
		mock_gbb.h.recovery_key_size - sizeof(mock_gbb.recovery_key);
	TEST_EQ(vb2api_kernel_phase1(ctx), VB2_SUCCESS,
		"phase1 rec workbuf key");
	TEST_EQ(sd->kernel_key_offset, 0, "  workbuf key offset");
	TEST_EQ(sd->kernel_key_size, 0, "  workbuf key size");
	mock_gbb.h.flags |= VB2_GBB_FLAG_FORCE_MANUAL_RECOVERY;
	TEST_ABORT(vb2api_kernel_phase1(ctx), "  fatal for manual recovery");

	reset_common_data(FOR_PHASE1);
	ctx->flags |= VB2_CONTEXT_RECOVERY_MODE;
	mock_read_res_fail_on_call = 1;
	TEST_EQ(vb2api_kernel_phase1(ctx), VB2_SUCCESS,
		"phase1 rec gbb read key");
	TEST_EQ(sd->kernel_key_offset, 0, "  workbuf key offset");
	TEST_EQ(sd->kernel_key_size, 0, "  workbuf key size");
	mock_gbb.h.flags |= VB2_GBB_FLAG_FORCE_MANUAL_RECOVERY;
	mock_read_res_fail_on_call = 1;
	TEST_ABORT(vb2api_kernel_phase1(ctx), "  fatal for manual recovery");

	/* Failures while parsing subkey from firmware preamble */
	reset_common_data(FOR_PHASE1);
	sd->preamble_size = 0;
	TEST_EQ(vb2api_kernel_phase1(ctx), VB2_ERROR_API_KPHASE1_PREAMBLE,
		"phase1 fw preamble");
}

static void normal_boot_tests(void)
{
	/*
	 * TODO: vb2_normal_boot() tests go here.  Relocate from
	 * vboot_legacy_clamshell_tests.c, and remove comment in
	 * vboot_legacy_menu_tests.c.
	 */
}

int main(int argc, char* argv[])
{
	phase1_tests();
	normal_boot_tests();

	return gTestSuccess ? 0 : 255;
}
