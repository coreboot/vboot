/* Copyright (c) 2014 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Tests for misc library
 */

#include <stdio.h>

#include "2api.h"
#include "2common.h"
#include "2misc.h"
#include "2nvstorage.h"
#include "2rsa.h"
#include "2secdata.h"
#include "2sysincludes.h"
#include "test_common.h"

/* Common context for tests */
static uint8_t workbuf[VB2_FIRMWARE_WORKBUF_RECOMMENDED_SIZE]
	__attribute__ ((aligned (VB2_WORKBUF_ALIGN)));
static struct vb2_context ctx;
static struct vb2_shared_data *sd;
static struct vb2_gbb_header gbb;

const char mock_body[320] = "Mock body";
const int mock_body_size = sizeof(mock_body);
const int mock_algorithm = VB2_ALG_RSA2048_SHA256;
const int mock_hash_alg = VB2_HASH_SHA256;
static const uint8_t mock_hwid_digest[VB2_GBB_HWID_DIGEST_SIZE] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
};

/* Mocked function data */
static int force_dev_mode;
static vb2_error_t retval_vb2_fw_init_gbb;
static vb2_error_t retval_vb2_check_dev_switch;
static vb2_error_t retval_vb2_check_tpm_clear;
static vb2_error_t retval_vb2_select_fw_slot;

/* Type of test to reset for */
enum reset_type {
	FOR_MISC,
};

static void reset_common_data(enum reset_type t)
{
	memset(workbuf, 0xaa, sizeof(workbuf));

	memset(&ctx, 0, sizeof(ctx));
	ctx.workbuf = workbuf;
	ctx.workbuf_size = sizeof(workbuf);

	vb2_init_context(&ctx);
	sd = vb2_get_sd(&ctx);

	vb2_nv_init(&ctx);

	vb2api_secdata_firmware_create(&ctx);
	vb2_secdata_firmware_init(&ctx);

	force_dev_mode = 0;
	retval_vb2_fw_init_gbb = VB2_SUCCESS;
	retval_vb2_check_dev_switch = VB2_SUCCESS;
	retval_vb2_check_tpm_clear = VB2_SUCCESS;
	retval_vb2_select_fw_slot = VB2_SUCCESS;

	memcpy(&gbb.hwid_digest, mock_hwid_digest,
	       sizeof(gbb.hwid_digest));
};

/* Mocked functions */
struct vb2_gbb_header *vb2_get_gbb(struct vb2_context *c)
{
	return &gbb;
}

vb2_error_t vb2_fw_init_gbb(struct vb2_context *c)
{
	return retval_vb2_fw_init_gbb;
}

vb2_error_t vb2_check_dev_switch(struct vb2_context *c)
{
	if (force_dev_mode)
		sd->flags |= VB2_SD_FLAG_DEV_MODE_ENABLED;
	return retval_vb2_check_dev_switch;
}

vb2_error_t vb2_check_tpm_clear(struct vb2_context *c)
{
	return retval_vb2_check_tpm_clear;
}

vb2_error_t vb2_select_fw_slot(struct vb2_context *c)
{
	return retval_vb2_select_fw_slot;
}

/* Tests */

static void misc_tests(void)
{
	/* Test secdata_firmware passthru functions */
	reset_common_data(FOR_MISC);
	/* Corrupt secdata_firmware so initial check will fail */
	ctx.secdata_firmware[0] ^= 0x42;
	TEST_EQ(vb2api_secdata_firmware_check(&ctx),
		VB2_ERROR_SECDATA_FIRMWARE_CRC,
		"secdata_firmware check");
	TEST_EQ(vb2api_secdata_firmware_create(&ctx), VB2_SECDATA_FIRMWARE_SIZE,
		  "secdata_firmware create");
	TEST_SUCC(vb2api_secdata_firmware_check(&ctx),
		  "secdata_firmware check 2");

	/* Test fail passthru */
	reset_common_data(FOR_MISC);
	vb2api_fail(&ctx, 12, 34);
	TEST_EQ(vb2_nv_get(&ctx, VB2_NV_RECOVERY_REQUEST),
		12, "vb2api_fail request");
	TEST_EQ(vb2_nv_get(&ctx, VB2_NV_RECOVERY_SUBCODE),
		34, "vb2api_fail subcode");
}

static void phase1_tests(void)
{
	reset_common_data(FOR_MISC);
	TEST_SUCC(vb2api_fw_phase1(&ctx), "phase1 good");
	TEST_EQ(sd->recovery_reason, 0, "  not recovery");
	TEST_EQ(ctx.flags & VB2_CONTEXT_RECOVERY_MODE, 0, "  recovery flag");
	TEST_EQ(ctx.flags & VB2_CONTEXT_CLEAR_RAM, 0, "  clear ram flag");
	TEST_EQ(ctx.flags & VB2_CONTEXT_DISPLAY_INIT,
		0, "  display init context flag");
	TEST_EQ(sd->flags & VB2_SD_FLAG_DISPLAY_AVAILABLE,
		0, "  display available SD flag");

	reset_common_data(FOR_MISC);
	retval_vb2_fw_init_gbb = VB2_ERROR_GBB_MAGIC;
	TEST_EQ(vb2api_fw_phase1(&ctx), VB2_ERROR_API_PHASE1_RECOVERY,
		"phase1 gbb");
	TEST_EQ(sd->recovery_reason, VB2_RECOVERY_GBB_HEADER,
		"  recovery reason");
	TEST_NEQ(ctx.flags & VB2_CONTEXT_RECOVERY_MODE, 0, "  recovery flag");
	TEST_NEQ(ctx.flags & VB2_CONTEXT_CLEAR_RAM, 0, "  clear ram flag");

	/* Dev switch error in normal mode reboots to recovery */
	reset_common_data(FOR_MISC);
	retval_vb2_check_dev_switch = VB2_ERROR_MOCK;
	TEST_EQ(vb2api_fw_phase1(&ctx), VB2_ERROR_MOCK, "phase1 dev switch");
	TEST_EQ(vb2_nv_get(&ctx, VB2_NV_RECOVERY_REQUEST),
		VB2_RECOVERY_DEV_SWITCH, "  recovery request");

	/* Dev switch error already in recovery mode just proceeds */
	reset_common_data(FOR_MISC);
	vb2_nv_set(&ctx, VB2_NV_RECOVERY_REQUEST, VB2_RECOVERY_RO_UNSPECIFIED);
	retval_vb2_check_dev_switch = VB2_ERROR_MOCK;
	TEST_EQ(vb2api_fw_phase1(&ctx), VB2_ERROR_API_PHASE1_RECOVERY,
		"phase1 dev switch error in recovery");
	TEST_EQ(sd->recovery_reason, VB2_RECOVERY_RO_UNSPECIFIED,
		"  recovery reason");
	/* Check that DISPLAY_AVAILABLE gets set on recovery mode. */
	TEST_NEQ(ctx.flags & VB2_CONTEXT_DISPLAY_INIT,
		 0, "  display init context flag");
	TEST_NEQ(sd->flags & VB2_SD_FLAG_DISPLAY_AVAILABLE,
		 0, "  display available SD flag");

	reset_common_data(FOR_MISC);
	ctx.secdata_firmware[0] ^= 0x42;
	TEST_EQ(vb2api_fw_phase1(&ctx), VB2_ERROR_API_PHASE1_RECOVERY,
		"phase1 secdata_firmware");
	TEST_EQ(sd->recovery_reason, VB2_RECOVERY_SECDATA_FIRMWARE_INIT,
		"  recovery reason");
	TEST_NEQ(ctx.flags & VB2_CONTEXT_RECOVERY_MODE, 0, "  recovery flag");
	TEST_NEQ(ctx.flags & VB2_CONTEXT_CLEAR_RAM, 0, "  clear ram flag");

	/* Test secdata_firmware-requested reboot */
	reset_common_data(FOR_MISC);
	ctx.flags |= VB2_CONTEXT_SECDATA_WANTS_REBOOT;
	TEST_EQ(vb2api_fw_phase1(&ctx), VB2_ERROR_API_PHASE1_SECDATA_REBOOT,
		"phase1 secdata_firmware reboot normal");
	TEST_EQ(sd->recovery_reason, 0,	"  recovery reason");
	TEST_EQ(vb2_nv_get(&ctx, VB2_NV_TPM_REQUESTED_REBOOT),
		1, "  tpm reboot request");
	TEST_EQ(vb2_nv_get(&ctx, VB2_NV_RECOVERY_REQUEST),
		0, "  recovery request");

	reset_common_data(FOR_MISC);
	vb2_nv_set(&ctx, VB2_NV_TPM_REQUESTED_REBOOT, 1);
	TEST_SUCC(vb2api_fw_phase1(&ctx),
		  "phase1 secdata_firmware reboot back normal");
	TEST_EQ(sd->recovery_reason, 0,	"  recovery reason");
	TEST_EQ(vb2_nv_get(&ctx, VB2_NV_TPM_REQUESTED_REBOOT),
		0, "  tpm reboot request");
	TEST_EQ(vb2_nv_get(&ctx, VB2_NV_RECOVERY_REQUEST),
		0, "  recovery request");

	reset_common_data(FOR_MISC);
	ctx.flags |= VB2_CONTEXT_SECDATA_WANTS_REBOOT;
	memset(ctx.secdata_firmware, 0, sizeof(ctx.secdata_firmware));
	TEST_EQ(vb2api_fw_phase1(&ctx), VB2_ERROR_API_PHASE1_SECDATA_REBOOT,
		"phase1 secdata_firmware reboot normal, "
		"secdata_firmware blank");
	TEST_EQ(sd->recovery_reason, 0,	"  recovery reason");
	TEST_EQ(vb2_nv_get(&ctx, VB2_NV_TPM_REQUESTED_REBOOT),
		1, "  tpm reboot request");
	TEST_EQ(vb2_nv_get(&ctx, VB2_NV_RECOVERY_REQUEST),
		0, "  recovery request");

	reset_common_data(FOR_MISC);
	ctx.flags |= VB2_CONTEXT_SECDATA_WANTS_REBOOT;
	vb2_nv_set(&ctx, VB2_NV_TPM_REQUESTED_REBOOT, 1);
	TEST_EQ(vb2api_fw_phase1(&ctx), VB2_ERROR_API_PHASE1_RECOVERY,
		"phase1 secdata_firmware reboot normal again");
	TEST_EQ(sd->recovery_reason, VB2_RECOVERY_RO_TPM_REBOOT,
		"  recovery reason");
	TEST_EQ(vb2_nv_get(&ctx, VB2_NV_TPM_REQUESTED_REBOOT),
		1, "  tpm reboot request");
	TEST_EQ(vb2_nv_get(&ctx, VB2_NV_RECOVERY_REQUEST),
		0, "  recovery request");

	reset_common_data(FOR_MISC);
	ctx.flags |= VB2_CONTEXT_SECDATA_WANTS_REBOOT;
	vb2_nv_set(&ctx, VB2_NV_RECOVERY_REQUEST, VB2_RECOVERY_RO_UNSPECIFIED);
	TEST_EQ(vb2api_fw_phase1(&ctx), VB2_ERROR_API_PHASE1_SECDATA_REBOOT,
		"phase1 secdata_firmware reboot recovery");
	/* Recovery reason isn't set this boot because we're rebooting first */
	TEST_EQ(sd->recovery_reason, 0, "  recovery reason not set THIS boot");
	TEST_EQ(vb2_nv_get(&ctx, VB2_NV_TPM_REQUESTED_REBOOT),
		1, "  tpm reboot request");
	TEST_EQ(vb2_nv_get(&ctx, VB2_NV_RECOVERY_REQUEST),
		VB2_RECOVERY_RO_UNSPECIFIED, "  recovery request not cleared");

	reset_common_data(FOR_MISC);
	vb2_nv_set(&ctx, VB2_NV_TPM_REQUESTED_REBOOT, 1);
	vb2_nv_set(&ctx, VB2_NV_RECOVERY_REQUEST, VB2_RECOVERY_RO_UNSPECIFIED);
	TEST_EQ(vb2api_fw_phase1(&ctx), VB2_ERROR_API_PHASE1_RECOVERY,
		"phase1 secdata_firmware reboot back recovery");
	TEST_EQ(sd->recovery_reason, VB2_RECOVERY_RO_UNSPECIFIED,
		"  recovery reason");
	TEST_EQ(vb2_nv_get(&ctx, VB2_NV_TPM_REQUESTED_REBOOT),
		0, "  tpm reboot request");
	TEST_EQ(vb2_nv_get(&ctx, VB2_NV_RECOVERY_REQUEST), 0,
		"  recovery request cleared");

	reset_common_data(FOR_MISC);
	ctx.flags |= VB2_CONTEXT_SECDATA_WANTS_REBOOT;
	vb2_nv_set(&ctx, VB2_NV_TPM_REQUESTED_REBOOT, 1);
	vb2_nv_set(&ctx, VB2_NV_RECOVERY_REQUEST, VB2_RECOVERY_RO_UNSPECIFIED);
	TEST_EQ(vb2api_fw_phase1(&ctx), VB2_ERROR_API_PHASE1_RECOVERY,
		"phase1 secdata_firmware reboot recovery again");
	TEST_EQ(sd->recovery_reason, VB2_RECOVERY_RO_UNSPECIFIED,
		"  recovery reason");
	TEST_EQ(vb2_nv_get(&ctx, VB2_NV_TPM_REQUESTED_REBOOT),
		1, "  tpm reboot request");
	TEST_EQ(vb2_nv_get(&ctx, VB2_NV_RECOVERY_REQUEST), 0,
		"  recovery request cleared");

	/* Cases for checking DISPLAY_INIT and DISPLAY_AVAILABLE. */
	reset_common_data(FOR_MISC);
	ctx.flags |= VB2_CONTEXT_DISPLAY_INIT;
	TEST_SUCC(vb2api_fw_phase1(&ctx), "phase1 with DISPLAY_INIT");
	TEST_NEQ(ctx.flags & VB2_CONTEXT_DISPLAY_INIT,
		 0, "  display init context flag");
	TEST_NEQ(sd->flags & VB2_SD_FLAG_DISPLAY_AVAILABLE,
		 0, "  display available SD flag");

	reset_common_data(FOR_MISC);
	vb2_nv_set(&ctx, VB2_NV_DISPLAY_REQUEST, 1);
	TEST_SUCC(vb2api_fw_phase1(&ctx), "phase1 with DISPLAY_REQUEST");
	TEST_NEQ(ctx.flags & VB2_CONTEXT_DISPLAY_INIT,
		 0, "  display init context flag");
	TEST_NEQ(sd->flags & VB2_SD_FLAG_DISPLAY_AVAILABLE,
		 0, "  display available SD flag");

	reset_common_data(FOR_MISC);
	force_dev_mode = 1;
	TEST_SUCC(vb2api_fw_phase1(&ctx), "phase1 in dev mode");
	TEST_NEQ(ctx.flags & VB2_CONTEXT_DISPLAY_INIT,
		 0, "  display init context flag");
	TEST_NEQ(sd->flags & VB2_SD_FLAG_DISPLAY_AVAILABLE,
		 0, "  display available SD flag");
}

static void phase2_tests(void)
{
	reset_common_data(FOR_MISC);
	TEST_SUCC(vb2api_fw_phase2(&ctx), "phase2 good");
	TEST_EQ(ctx.flags & VB2_CONTEXT_CLEAR_RAM, 0, "  clear ram flag");
	TEST_EQ(ctx.flags & VB2_CONTEXT_FW_SLOT_B, 0, "  slot b flag");

	reset_common_data(FOR_MISC);
	ctx.flags |= VB2_CONTEXT_DEVELOPER_MODE;
	TEST_SUCC(vb2api_fw_phase2(&ctx), "phase2 dev");
	TEST_NEQ(ctx.flags & VB2_CONTEXT_CLEAR_RAM, 0, "  clear ram flag");

	reset_common_data(FOR_MISC);
	retval_vb2_check_tpm_clear = VB2_ERROR_MOCK;
	TEST_EQ(vb2api_fw_phase2(&ctx), VB2_ERROR_MOCK, "phase2 tpm clear");
	TEST_EQ(vb2_nv_get(&ctx, VB2_NV_RECOVERY_REQUEST),
		VB2_RECOVERY_TPM_CLEAR_OWNER, "  recovery reason");

	reset_common_data(FOR_MISC);
	retval_vb2_select_fw_slot = VB2_ERROR_MOCK;
	TEST_EQ(vb2api_fw_phase2(&ctx), VB2_ERROR_MOCK, "phase2 slot");
	TEST_EQ(vb2_nv_get(&ctx, VB2_NV_RECOVERY_REQUEST),
		VB2_RECOVERY_FW_SLOT, "  recovery reason");

	/* S3 resume exits before clearing RAM */
	reset_common_data(FOR_MISC);
	ctx.flags |= VB2_CONTEXT_S3_RESUME;
	ctx.flags |= VB2_CONTEXT_DEVELOPER_MODE;
	TEST_SUCC(vb2api_fw_phase2(&ctx), "phase2 s3 dev");
	TEST_EQ(ctx.flags & VB2_CONTEXT_CLEAR_RAM, 0, "  clear ram flag");
	TEST_EQ(ctx.flags & VB2_CONTEXT_FW_SLOT_B, 0, "  slot b flag");

	reset_common_data(FOR_MISC);
	ctx.flags |= VB2_CONTEXT_S3_RESUME;
	vb2_nv_set(&ctx, VB2_NV_FW_TRIED, 1);
	TEST_SUCC(vb2api_fw_phase2(&ctx), "phase2 s3");
	TEST_NEQ(ctx.flags & VB2_CONTEXT_FW_SLOT_B, 0, "  slot b flag");
}

static void get_pcr_digest_tests(void)
{
	uint8_t digest[VB2_PCR_DIGEST_RECOMMENDED_SIZE];
	uint8_t digest_org[VB2_PCR_DIGEST_RECOMMENDED_SIZE];
	uint32_t digest_size;

	reset_common_data(FOR_MISC);
	memset(digest_org, 0, sizeof(digest_org));

	digest_size = sizeof(digest);
	memset(digest, 0, sizeof(digest));
	TEST_SUCC(vb2api_get_pcr_digest(
			&ctx, BOOT_MODE_PCR, digest, &digest_size),
		  "BOOT_MODE_PCR");
	TEST_EQ(digest_size, VB2_SHA1_DIGEST_SIZE, "BOOT_MODE_PCR digest size");
	TEST_TRUE(memcmp(digest, digest_org, digest_size),
		  "BOOT_MODE_PCR digest");

	digest_size = sizeof(digest);
	memset(digest, 0, sizeof(digest));
	TEST_SUCC(vb2api_get_pcr_digest(
			&ctx, HWID_DIGEST_PCR, digest, &digest_size),
		  "HWID_DIGEST_PCR");
	TEST_EQ(digest_size, VB2_GBB_HWID_DIGEST_SIZE,
		"HWID_DIGEST_PCR digest size");
	TEST_FALSE(memcmp(digest, mock_hwid_digest, digest_size),
		   "HWID_DIGEST_PCR digest");

	digest_size = 1;
	TEST_EQ(vb2api_get_pcr_digest(&ctx, BOOT_MODE_PCR, digest, &digest_size),
		VB2_ERROR_API_PCR_DIGEST_BUF,
		"BOOT_MODE_PCR buffer too small");

	TEST_EQ(vb2api_get_pcr_digest(
			&ctx, HWID_DIGEST_PCR + 1, digest, &digest_size),
		VB2_ERROR_API_PCR_DIGEST,
		"invalid enum vb2_pcr_digest");
}

int main(int argc, char* argv[])
{
	misc_tests();
	phase1_tests();
	phase2_tests();

	get_pcr_digest_tests();

	return gTestSuccess ? 0 : 255;
}
