/* Copyright (c) 2013 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Functions for querying, manipulating and locking secure data spaces
 * stored in the TPM NVRAM.
 */

#include "2api.h"
#include "2common.h"
#include "secdata_tpm.h"
#include "tlcl.h"
#include "tss_constants.h"
#include "vboot_test.h"

#define RETURN_ON_FAILURE(tpm_command) do { \
		uint32_t result_; \
		if ((result_ = (tpm_command)) != TPM_SUCCESS) { \
			VB2_DEBUG("TPM: %#x returned by " #tpm_command \
				  "\n", (int)result_); \
			return result_; \
		} \
	} while (0)

#define PRINT_BYTES(title, value) do { \
		int i; \
		VB2_DEBUG(title); \
		VB2_DEBUG_RAW(":"); \
		for (i = 0; i < sizeof(*(value)); i++) \
			VB2_DEBUG_RAW(" %02x", *((uint8_t *)(value) + i)); \
		VB2_DEBUG_RAW("\n"); \
	} while (0)

/* Keeps track of whether the kernel space has already been locked or not. */
int secdata_kernel_locked = 0;

/**
 * Issue a TPM_Clear and reenable/reactivate the TPM.
 */
uint32_t tlcl_clear_and_reenable(void)
{
	VB2_DEBUG("TPM: clear_and_reenable\n");
	RETURN_ON_FAILURE(TlclForceClear());
	RETURN_ON_FAILURE(TlclSetEnable());
	RETURN_ON_FAILURE(TlclSetDeactivated(0));

	return TPM_SUCCESS;
}

/**
 * Like TlclWrite(), but checks for write errors due to hitting the 64-write
 * limit and clears the TPM when that happens.  This can only happen when the
 * TPM is unowned, so it is OK to clear it (and we really have no choice).
 * This is not expected to happen frequently, but it could happen.
 */
uint32_t tlcl_safe_write(uint32_t index, const void *data, uint32_t length)
{
	uint32_t result = TlclWrite(index, data, length);
	if (result == TPM_E_MAXNVWRITES) {
		RETURN_ON_FAILURE(tlcl_clear_and_reenable());
		return TlclWrite(index, data, length);
	} else {
		return result;
	}
}

/* Functions to read and write firmware and kernel spaces. */

uint32_t secdata_firmware_write(struct vb2_context *ctx)
{
	if (!(ctx->flags & VB2_CONTEXT_SECDATA_FIRMWARE_CHANGED)) {
		VB2_DEBUG("TPM: secdata_firmware unchanged\n");
		return TPM_SUCCESS;
	}

	if (!(ctx->flags & VB2_CONTEXT_RECOVERY_MODE)) {
		VB2_DEBUG("Error: secdata_firmware modified "
			  "in non-recovery mode?\n");
		return TPM_E_AREA_LOCKED;
	}

	PRINT_BYTES("TPM: write secdata_firmware", &ctx->secdata_firmware);
	RETURN_ON_FAILURE(tlcl_safe_write(FIRMWARE_NV_INDEX,
					  ctx->secdata_firmware,
					  VB2_SECDATA_FIRMWARE_SIZE));

	ctx->flags &= ~VB2_CONTEXT_SECDATA_FIRMWARE_CHANGED;
	return TPM_SUCCESS;
}

uint32_t secdata_kernel_read(struct vb2_context *ctx)
{
#ifndef TPM2_MODE
	/*
	 * Before reading the kernel space, verify its permissions.  If the
	 * kernel space has the wrong permission, we give up.  This will need
	 * to be fixed by the recovery kernel.  We will have to worry about
	 * this because at any time (even with PP turned off) the TPM owner can
	 * remove and redefine a PP-protected space (but not write to it).
	 */
	uint32_t perms;

	RETURN_ON_FAILURE(TlclGetPermissions(KERNEL_NV_INDEX, &perms));
	if (perms != TPM_NV_PER_PPWRITE) {
		VB2_DEBUG("TPM: invalid secdata_kernel permissions: %#x\n",
			  perms);
		return TPM_E_CORRUPTED_STATE;
	}
#endif

	RETURN_ON_FAILURE(TlclRead(KERNEL_NV_INDEX, ctx->secdata_kernel,
				   VB2_SECDATA_KERNEL_SIZE));

	PRINT_BYTES("TPM: read secdata_kernel", &ctx->secdata_kernel);

	if (vb2api_secdata_kernel_check(ctx)) {
		VB2_DEBUG("TPM: secdata_kernel invalid (corrupted?)\n");
		return TPM_E_CORRUPTED_STATE;
	}

	return TPM_SUCCESS;
}

uint32_t secdata_kernel_write(struct vb2_context *ctx)
{
	if (!(ctx->flags & VB2_CONTEXT_SECDATA_KERNEL_CHANGED)) {
		VB2_DEBUG("TPM: secdata_kernel unchanged\n");
		return TPM_SUCCESS;
	}

	PRINT_BYTES("TPM: write secdata_kernel", &ctx->secdata_kernel);

	RETURN_ON_FAILURE(tlcl_safe_write(KERNEL_NV_INDEX, ctx->secdata_kernel,
					  VB2_SECDATA_KERNEL_SIZE));

	ctx->flags &= ~VB2_CONTEXT_SECDATA_KERNEL_CHANGED;
	return TPM_SUCCESS;
}

uint32_t secdata_kernel_lock(struct vb2_context *ctx)
{
	/* Skip if already locked */
	if (secdata_kernel_locked) {
		VB2_DEBUG("TPM: secdata_kernel already locked; skipping\n");
		return TPM_SUCCESS;
	}

	RETURN_ON_FAILURE(TlclLockPhysicalPresence());

	VB2_DEBUG("TPM: secdata_kernel locked\n");
	secdata_kernel_locked = 1;
	return TPM_SUCCESS;
}

uint32_t secdata_fwmp_read(struct vb2_context *ctx)
{
	vb2_error_t rv;
	uint8_t size = VB2_SECDATA_FWMP_MIN_SIZE;
	uint32_t r;

	/* Try to read entire 1.0 struct */
	r = TlclRead(FWMP_NV_INDEX, ctx->secdata_fwmp, size);
	if (TPM_E_BADINDEX == r) {
		/* Missing space is not an error; tell vboot */
		VB2_DEBUG("TPM: no secdata_fwmp space\n");
		ctx->flags |= VB2_CONTEXT_NO_SECDATA_FWMP;
		return TPM_SUCCESS;
	} else if (TPM_SUCCESS != r) {
		VB2_DEBUG("TPM: read secdata_fwmp returned %#x\n", r);
		return r;
	}

	/* Re-read more data if necessary */
	rv = vb2api_secdata_fwmp_check(ctx, &size);
	if (rv == VB2_SUCCESS)
		return VB2_SUCCESS;

	if (rv == VB2_ERROR_SECDATA_FWMP_INCOMPLETE) {
		RETURN_ON_FAILURE(TlclRead(FWMP_NV_INDEX, ctx->secdata_fwmp,
					   size));

		/* Check one more time */
		if (vb2api_secdata_fwmp_check(ctx, &size) == VB2_SUCCESS)
			return VB2_SUCCESS;
	}

	VB2_DEBUG("TPM: secdata_fwmp invalid (corrupted?)\n");
	return TPM_E_CORRUPTED_STATE;
}
