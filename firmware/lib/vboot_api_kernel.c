/* Copyright (c) 2013 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * High-level firmware wrapper API - entry points for kernel selection
 */

#include "2common.h"
#include "2misc.h"
#include "2nvstorage.h"
#include "2rsa.h"
#include "2secdata.h"
#include "2sysincludes.h"
#include "ec_sync.h"
#include "load_kernel_fw.h"
#include "secdata_tpm.h"
#include "utility.h"
#include "vb2_common.h"
#include "vboot_api.h"
#include "vboot_common.h"
#include "vboot_kernel.h"
#include "vboot_test.h"

/* Global variables */
static struct RollbackSpaceFwmp fwmp;
static LoadKernelParams lkp;

#ifdef CHROMEOS_ENVIRONMENT
/* Global variable accessors for unit tests */

struct RollbackSpaceFwmp *VbApiKernelGetFwmp(void)
{
	return &fwmp;
}

struct LoadKernelParams *VbApiKernelGetParams(void)
{
	return &lkp;
}

#endif

/**
 * Set recovery request (called from vboot_api_kernel.c functions only)
 */
static void VbSetRecoveryRequest(struct vb2_context *ctx,
				 uint32_t recovery_request)
{
	VB2_DEBUG("VbSetRecoveryRequest(%d)\n", (int)recovery_request);
	vb2_nv_set(ctx, VB2_NV_RECOVERY_REQUEST, recovery_request);
}

void vb2_nv_commit(struct vb2_context *ctx)
{
	/* Exit if nothing has changed */
	if (!(ctx->flags & VB2_CONTEXT_NVDATA_CHANGED))
		return;

	ctx->flags &= ~VB2_CONTEXT_NVDATA_CHANGED;
	VbExNvStorageWrite(ctx->nvdata);
}

uint32_t vb2_get_fwmp_flags(void)
{
	return fwmp.flags;
}

vb2_error_t VbTryLoadKernel(struct vb2_context *ctx, uint32_t get_info_flags)
{
	vb2_error_t retval = VB2_ERROR_UNKNOWN;
	VbDiskInfo* disk_info = NULL;
	uint32_t disk_count = 0;
	uint32_t i;

	VB2_DEBUG("VbTryLoadKernel() start, get_info_flags=0x%x\n",
		  (unsigned)get_info_flags);

	lkp.fwmp = &fwmp;
	lkp.disk_handle = NULL;

	/* Find disks */
	if (VB2_SUCCESS != VbExDiskGetInfo(&disk_info, &disk_count,
					   get_info_flags))
		disk_count = 0;

	VB2_DEBUG("VbTryLoadKernel() found %d disks\n", (int)disk_count);
	if (0 == disk_count) {
		VbSetRecoveryRequest(ctx, VB2_RECOVERY_RW_NO_DISK);
		return VBERROR_NO_DISK_FOUND;
	}

	/* Loop over disks */
	for (i = 0; i < disk_count; i++) {
		VB2_DEBUG("VbTryLoadKernel() trying disk %d\n", (int)i);
		/*
		 * Sanity-check what we can. FWIW, VbTryLoadKernel() is always
		 * called with only a single bit set in get_info_flags.
		 *
		 * Ensure that we got a partition with only the flags we asked
		 * for.
		 */
		if (disk_info[i].bytes_per_lba < 512 ||
			(disk_info[i].bytes_per_lba &
				(disk_info[i].bytes_per_lba  - 1)) != 0 ||
					16 > disk_info[i].lba_count ||
					get_info_flags != (disk_info[i].flags &
					~VB_DISK_FLAG_EXTERNAL_GPT)) {
			VB2_DEBUG("  skipping: bytes_per_lba=%" PRIu64
				  " lba_count=%" PRIu64 " flags=0x%x\n",
				  disk_info[i].bytes_per_lba,
				  disk_info[i].lba_count,
				  disk_info[i].flags);
			continue;
		}
		lkp.disk_handle = disk_info[i].handle;
		lkp.bytes_per_lba = disk_info[i].bytes_per_lba;
		lkp.gpt_lba_count = disk_info[i].lba_count;
		lkp.streaming_lba_count = disk_info[i].streaming_lba_count
						?: lkp.gpt_lba_count;
		lkp.boot_flags |= disk_info[i].flags & VB_DISK_FLAG_EXTERNAL_GPT
				? BOOT_FLAG_EXTERNAL_GPT : 0;
		retval = LoadKernel(ctx, &lkp);

		VB2_DEBUG("VbTryLoadKernel() LoadKernel() = %d\n", retval);

		/*
		 * Stop now if we found a kernel.
		 *
		 * TODO: If recovery requested, should track the farthest we
		 * get, instead of just returning the value from the last disk
		 * attempted.
		 */
		if (VB2_SUCCESS == retval)
			break;
	}

	/* If we didn't find any good kernels, don't return a disk handle. */
	if (VB2_SUCCESS != retval) {
		VbSetRecoveryRequest(ctx, VB2_RECOVERY_RW_NO_KERNEL);
		lkp.disk_handle = NULL;
	}

	VbExDiskFreeInfo(disk_info, lkp.disk_handle);

	/*
	 * Pass through return code.  Recovery reason (if any) has already been
	 * set by LoadKernel().
	 */
	return retval;
}

/**
 * Reset any NVRAM requests.
 *
 * @param ctx		Vboot context
 * @return 1 if a reboot is required, 0 otherwise.
 */
static int vb2_reset_nv_requests(struct vb2_context *ctx)
{
	int need_reboot = 0;

	if (vb2_nv_get(ctx, VB2_NV_DISPLAY_REQUEST)) {
		VB2_DEBUG("Unset display request (undo display init)\n");
		vb2_nv_set(ctx, VB2_NV_DISPLAY_REQUEST, 0);
		need_reboot = 1;
	}

	if (vb2_nv_get(ctx, VB2_NV_DIAG_REQUEST)) {
		VB2_DEBUG("Unset diagnostic request (undo display init)\n");
		vb2_nv_set(ctx, VB2_NV_DIAG_REQUEST, 0);
		need_reboot = 1;
	}

	return need_reboot;
}

vb2_error_t VbBootNormal(struct vb2_context *ctx)
{
	struct vb2_shared_data *sd = vb2_get_sd(ctx);
	VbSharedDataHeader *shared = sd->vbsd;
	uint32_t max_rollforward = vb2_nv_get(ctx,
					      VB2_NV_KERNEL_MAX_ROLLFORWARD);

	/* Boot from fixed disk only */
	VB2_DEBUG("Entering\n");

	if (vb2_reset_nv_requests(ctx)) {
		VB2_DEBUG("Normal mode: reboot to reset NVRAM requests\n");
		return VBERROR_REBOOT_REQUIRED;
	}

	vb2_error_t rv = VbTryLoadKernel(ctx, VB_DISK_FLAG_FIXED);

	VB2_DEBUG("Checking if TPM kernel version needs advancing\n");

	if ((1 == shared->firmware_index) && (shared->flags & VBSD_FWB_TRIED)) {
		/*
		 * Special cases for when we're trying a new firmware B.  These
		 * are needed because firmware updates also usually change the
		 * kernel key, which means that the B firmware can only boot a
		 * new kernel, and the old firmware in A can only boot the
		 * previous kernel.
		 *
		 * Don't advance the TPM if we're trying a new firmware B,
		 * because we don't yet know if the new kernel will
		 * successfully boot.  We still want to be able to fall back to
		 * the previous firmware+kernel if the new firmware+kernel
		 * fails.
		 *
		 * If we found only invalid kernels, reboot and try again.
		 * This allows us to fall back to the previous firmware+kernel
		 * instead of giving up and going to recovery mode right away.
		 * We'll still go to recovery mode if we run out of tries and
		 * the old firmware can't find a kernel it likes.
		 */
		if (rv == VBERROR_INVALID_KERNEL_FOUND) {
			VB2_DEBUG("Trying FW B; only found invalid kernels.\n");
			VbSetRecoveryRequest(ctx, VB2_RECOVERY_NOT_REQUESTED);
		}

		return rv;
	}

	/*
	 * Limit kernel version rollforward if needed.  Can't limit kernel
	 * version to less than the version currently in the TPM.  That is,
	 * we're limiting rollforward, not allowing rollback.
	 */
	if (max_rollforward < shared->kernel_version_tpm_start)
		max_rollforward = shared->kernel_version_tpm_start;

	if (shared->kernel_version_tpm > max_rollforward) {
		VB2_DEBUG("Limiting TPM kernel version roll-forward "
			  "to 0x%x < 0x%x\n",
			  max_rollforward, shared->kernel_version_tpm);

		shared->kernel_version_tpm = max_rollforward;
	}

	if ((shared->kernel_version_tpm > shared->kernel_version_tpm_start) &&
	    RollbackKernelWrite(shared->kernel_version_tpm)) {
		VB2_DEBUG("Error writing kernel versions to TPM.\n");
		VbSetRecoveryRequest(ctx, VB2_RECOVERY_RW_TPM_W_ERROR);
		return VBERROR_TPM_WRITE_KERNEL;
	}

	return rv;
}

static vb2_error_t vb2_kernel_setup(struct vb2_context *ctx,
				    VbSharedDataHeader *shared,
				    VbSelectAndLoadKernelParams *kparams)
{
	if (VB2_SUCCESS != vb2_init_context(ctx)) {
		VB2_DEBUG("Can't init vb2_context\n");
		VbSetRecoveryRequest(ctx, VB2_RECOVERY_RW_SHARED_DATA);
		return VBERROR_INIT_SHARED_DATA;
	}

	/* Start timer */
	shared->timer_vb_select_and_load_kernel_enter = VbExGetTimer();

	/* Translate vboot1 flags back to vboot2 */
	if (shared->recovery_reason)
		ctx->flags |= VB2_CONTEXT_RECOVERY_MODE;
	if (shared->flags & VBSD_BOOT_DEV_SWITCH_ON)
		ctx->flags |= VB2_CONTEXT_DEVELOPER_MODE;

	/*
	 * The following flags are set by depthcharge.
	 *
	 * TODO: Some of these are set at compile-time, so could be #defines
	 * instead of flags.  That would save on firmware image size because
	 * features that won't be used in an image could be compiled out.
	 */
	if (shared->flags & VBSD_EC_SOFTWARE_SYNC)
		ctx->flags |= VB2_CONTEXT_EC_SYNC_SUPPORTED;
	if (shared->flags & VBSD_EC_SLOW_UPDATE)
		ctx->flags |= VB2_CONTEXT_EC_SYNC_SLOW;
	if (shared->flags & VBSD_EC_EFS)
		ctx->flags |= VB2_CONTEXT_EC_EFS;
	if (shared->flags & VBSD_NVDATA_V2)
		ctx->flags |= VB2_CONTEXT_NVDATA_V2;

	VbExNvStorageRead(ctx->nvdata);
	vb2_nv_init(ctx);

	struct vb2_shared_data *sd = vb2_get_sd(ctx);
	struct vb2_gbb_header *gbb = vb2_get_gbb(ctx);
	sd->recovery_reason = shared->recovery_reason;

	/*
	 * Save a pointer to the old vboot1 shared data, since we haven't
	 * finished porting the library to use the new vb2 context and shared
	 * data.
	 *
	 * TODO: replace this with fields directly in vb2 shared data.
	 */
	sd->vbsd = shared;

	/*
	 * If we're in recovery mode just to do memory retraining, all we
	 * need to do is reboot.
	 */
	if (sd->recovery_reason == VB2_RECOVERY_TRAIN_AND_REBOOT) {
		VB2_DEBUG("Reboot after retraining in recovery.\n");
		return VBERROR_REBOOT_REQUIRED;
	}

	/* Fill in params for calls to LoadKernel() */
	memset(&lkp, 0, sizeof(lkp));
	lkp.kernel_buffer = kparams->kernel_buffer;
	lkp.kernel_buffer_size = kparams->kernel_buffer_size;

	/* Clear output params in case we fail */
	kparams->disk_handle = NULL;
	kparams->partition_number = 0;
	kparams->bootloader_address = 0;
	kparams->bootloader_size = 0;
	kparams->flags = 0;
	memset(kparams->partition_guid, 0, sizeof(kparams->partition_guid));

	/* Read kernel version from the TPM.  Ignore errors in recovery mode. */
	if (RollbackKernelRead(&shared->kernel_version_tpm)) {
		VB2_DEBUG("Unable to get kernel versions from TPM\n");
		if (!(ctx->flags & VB2_CONTEXT_RECOVERY_MODE)) {
			VbSetRecoveryRequest(ctx, VB2_RECOVERY_RW_TPM_R_ERROR);
			return VBERROR_TPM_READ_KERNEL;
		}
	}

	shared->kernel_version_tpm_start = shared->kernel_version_tpm;

	/* Read FWMP.  Ignore errors in recovery mode. */
	if (gbb->flags & VB2_GBB_FLAG_DISABLE_FWMP) {
		memset(&fwmp, 0, sizeof(fwmp));
	} else if (RollbackFwmpRead(&fwmp)) {
		VB2_DEBUG("Unable to get FWMP from TPM\n");
		if (!(ctx->flags & VB2_CONTEXT_RECOVERY_MODE)) {
			VbSetRecoveryRequest(ctx, VB2_RECOVERY_RW_TPM_R_ERROR);
			return VBERROR_TPM_READ_FWMP;
		}
	}

	return VB2_SUCCESS;
}

static vb2_error_t vb2_kernel_phase4(struct vb2_context *ctx,
				     VbSelectAndLoadKernelParams *kparams)
{
	struct vb2_shared_data *sd = vb2_get_sd(ctx);

	/* Save disk parameters */
	kparams->disk_handle = lkp.disk_handle;
	kparams->partition_number = lkp.partition_number;
	kparams->bootloader_address = lkp.bootloader_address;
	kparams->bootloader_size = lkp.bootloader_size;
	kparams->flags = lkp.flags;
	kparams->kernel_buffer = lkp.kernel_buffer;
	kparams->kernel_buffer_size = lkp.kernel_buffer_size;
	memcpy(kparams->partition_guid, lkp.partition_guid,
	       sizeof(kparams->partition_guid));

	/* Lock the kernel versions if not in recovery mode */
	if (!(ctx->flags & VB2_CONTEXT_RECOVERY_MODE) &&
	    RollbackKernelLock(sd->recovery_reason)) {
		VB2_DEBUG("Error locking kernel versions.\n");
		VbSetRecoveryRequest(ctx, VB2_RECOVERY_RW_TPM_L_ERROR);
		return VBERROR_TPM_LOCK_KERNEL;
	}

	return VB2_SUCCESS;
}

static void vb2_kernel_cleanup(struct vb2_context *ctx)
{
	vb2_nv_commit(ctx);

	/* vb2_shared_data may not have been initialized, and we may not have a
	   proper vbsd value. */
	struct vb2_shared_data *sd = vb2_get_sd(ctx);
	if (sd->vbsd)
		/* Stop timer */
		sd->vbsd->timer_vb_select_and_load_kernel_exit = VbExGetTimer();
}

vb2_error_t VbSelectAndLoadKernel(struct vb2_context *ctx,
				  VbSharedDataHeader *shared,
				  VbSelectAndLoadKernelParams *kparams)
{
	vb2_error_t retval = vb2_kernel_setup(ctx, shared, kparams);
	if (retval)
		goto VbSelectAndLoadKernel_exit;

	VB2_DEBUG("GBB flags are %#x\n", vb2_get_gbb(ctx)->flags);

	/*
	 * Do EC software sync unless we're in recovery mode. This has UI but
	 * it's just a single non-interactive WAIT screen.
	 */
	if (!(ctx->flags & VB2_CONTEXT_RECOVERY_MODE)) {
		retval = ec_sync_all(ctx);
		if (retval)
			goto VbSelectAndLoadKernel_exit;
	}

	/* Select boot path */
	if (ctx->flags & VB2_CONTEXT_RECOVERY_MODE) {
		/* Recovery boot.  This has UI. */
		if (kparams->inflags & VB_SALK_INFLAGS_ENABLE_DETACHABLE_UI)
			retval = VbBootRecoveryMenu(ctx);
		else
			retval = VbBootRecovery(ctx);
		VbExEcEnteringMode(0, VB_EC_RECOVERY);
	} else if (DIAGNOSTIC_UI && vb2_nv_get(ctx, VB2_NV_DIAG_REQUEST)) {
		vb2_nv_set(ctx, VB2_NV_DIAG_REQUEST, 0);

		/*
		 * Diagnostic boot. This has a UI but only power button
		 * is used for input so no detachable-specific UI is
		 * needed.  This mode is also 1-shot so it's placed
		 * before developer mode.
		 */
		retval = VbBootDiagnostic(ctx);
		/*
		 * The diagnostic menu should either boot a rom, or
		 * return either of reboot or shutdown.  The following
		 * check is a safety precaution.
		 */
		if (!retval)
			retval = VBERROR_REBOOT_REQUIRED;
	} else if (ctx->flags & VB2_CONTEXT_DEVELOPER_MODE) {
		if (kparams->inflags & VB_SALK_INFLAGS_VENDOR_DATA_SETTABLE)
			ctx->flags |= VB2_CONTEXT_VENDOR_DATA_SETTABLE;

		/* Developer boot.  This has UI. */
		if (kparams->inflags & VB_SALK_INFLAGS_ENABLE_DETACHABLE_UI)
			retval = VbBootDeveloperMenu(ctx);
		else
			retval = VbBootDeveloper(ctx);
		VbExEcEnteringMode(0, VB_EC_DEVELOPER);
	} else {
		/* Normal boot */
		retval = VbBootNormal(ctx);
		VbExEcEnteringMode(0, VB_EC_NORMAL);
	}

 VbSelectAndLoadKernel_exit:

	if (VB2_SUCCESS == retval)
		retval = vb2_kernel_phase4(ctx, kparams);

	vb2_kernel_cleanup(ctx);

	/* Pass through return value from boot path */
	VB2_DEBUG("Returning %d\n", (int)retval);
	return retval;
}

vb2_error_t VbVerifyMemoryBootImage(struct vb2_context *ctx,
				    VbSharedDataHeader *shared,
				    VbSelectAndLoadKernelParams *kparams,
				    void *boot_image, size_t image_size)
{
	struct vb2_packed_key *kernel_subkey = NULL;
	uint8_t *kbuf;
	VbKeyBlockHeader *key_block;
	VbKernelPreambleHeader *preamble;
	uint64_t body_offset;
	int hash_only = 0;
	int dev_switch;
	struct vb2_workbuf wb;
	vb2_error_t retval;
	vb2_error_t rv;

	/* Allocate work buffer */
	vb2_workbuf_from_ctx(ctx, &wb);

	retval = vb2_kernel_setup(ctx, shared, kparams);
	if (retval)
		goto fail;

	if ((boot_image == NULL) || (image_size == 0)) {
		retval = VB2_ERROR_INVALID_PARAMETER;
		goto fail;
	}

	kbuf = boot_image;

	/* Get recovery key. */
	rv = vb2_gbb_read_recovery_key(ctx, &kernel_subkey, NULL, &wb);
	if (VB2_SUCCESS != rv) {
		VB2_DEBUG("GBB read recovery key failed.\n");
		retval = VBERROR_INVALID_GBB;
		goto fail;
	}

	/* If we fail at any step, retval returned would be invalid kernel. */
	retval = VBERROR_INVALID_KERNEL_FOUND;

	/* Verify the key block. */
	key_block = (VbKeyBlockHeader *)kbuf;
	struct vb2_keyblock *keyblock2 = (struct vb2_keyblock *)kbuf;
	rv = VB2_SUCCESS;
	if (hash_only) {
		rv = vb2_verify_keyblock_hash(keyblock2, image_size, &wb);
	} else {
		/* Unpack kernel subkey */
		struct vb2_public_key kernel_subkey2;
		if (VB2_SUCCESS !=
		    vb2_unpack_key(&kernel_subkey2, kernel_subkey)) {
			VB2_DEBUG("Unable to unpack kernel subkey\n");
			goto fail;
		}
		rv = vb2_verify_keyblock(keyblock2, image_size,
					 &kernel_subkey2, &wb);
	}

	if (VB2_SUCCESS != rv) {
		VB2_DEBUG("Verifying key block signature/hash failed.\n");
		goto fail;
	}

	/* Check the key block flags against the current boot mode. */
	dev_switch = shared->flags & VBSD_BOOT_DEV_SWITCH_ON;
	if (!(key_block->key_block_flags &
	      (dev_switch ? KEY_BLOCK_FLAG_DEVELOPER_1 :
	       KEY_BLOCK_FLAG_DEVELOPER_0))) {
		VB2_DEBUG("Key block developer flag mismatch.\n");
		if (hash_only == 0)
			goto fail;
	}

	if (!(key_block->key_block_flags & KEY_BLOCK_FLAG_RECOVERY_1)) {
		VB2_DEBUG("Key block recovery flag mismatch.\n");
		if (hash_only == 0)
			goto fail;
	}

	/* Get key for preamble/data verification from the key block. */
	struct vb2_public_key data_key2;
	if (VB2_SUCCESS != vb2_unpack_key(&data_key2, &keyblock2->data_key)) {
		VB2_DEBUG("Unable to unpack kernel data key\n");
		goto fail;
	}

	/* Verify the preamble, which follows the key block */
	preamble = (VbKernelPreambleHeader *)(kbuf + key_block->key_block_size);
	struct vb2_kernel_preamble *preamble2 =
			(struct vb2_kernel_preamble *)
			(kbuf + key_block->key_block_size);

	if (VB2_SUCCESS != vb2_verify_kernel_preamble(
			preamble2,
			image_size - key_block->key_block_size,
			&data_key2,
			&wb)) {
		VB2_DEBUG("Preamble verification failed.\n");
		goto fail;
	}

	VB2_DEBUG("Kernel preamble is good.\n");

	/* Verify kernel data */
	body_offset = key_block->key_block_size + preamble->preamble_size;
	if (VB2_SUCCESS != vb2_verify_data(
			(const uint8_t *)(kbuf + body_offset),
			image_size - body_offset,
			(struct vb2_signature *)&preamble->body_signature,
			&data_key2, &wb)) {
		VB2_DEBUG("Kernel data verification failed.\n");
		goto fail;
	}

	VB2_DEBUG("Kernel is good.\n");

	/* Fill in output parameters. */
	kparams->kernel_buffer = kbuf + body_offset;
	kparams->kernel_buffer_size = image_size - body_offset;
	kparams->bootloader_address = preamble->bootloader_address;
	kparams->bootloader_size = preamble->bootloader_size;
	if (VbKernelHasFlags(preamble) == VBOOT_SUCCESS)
		kparams->flags = preamble->flags;

	retval = VB2_SUCCESS;

 fail:
	vb2_kernel_cleanup(ctx);
	return retval;
}
