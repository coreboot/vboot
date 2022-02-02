/* Copyright (c) 2013 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * High-level firmware wrapper API - entry points for kernel selection
 */

#include "2api.h"
#include "2common.h"
#include "2kernel.h"
#include "2misc.h"
#include "2nvstorage.h"
#include "2rsa.h"
#include "2secdata.h"
#include "2sysincludes.h"
#include "load_kernel_fw.h"
#include "vboot_api.h"
#include "vboot_struct.h"
#include "vboot_test.h"

/* Global variables */
static VbSelectAndLoadKernelParams *kparams_ptr;

#ifdef CHROMEOS_ENVIRONMENT
/* Global variable accessor for unit tests */
struct VbSelectAndLoadKernelParams **VbApiKernelGetParamsPtr(void)
{
	return &kparams_ptr;
}
#endif

static vb2_error_t handle_battery_cutoff(struct vb2_context *ctx)
{
	/*
	 * Check if we need to cut-off battery. This should be done after EC
	 * FW and auxfw are updated, and before the kernel is started.  This
	 * is to make sure all firmware is up-to-date before shipping (which
	 * is the typical use-case for cutoff).
	 */
	if (vb2_nv_get(ctx, VB2_NV_BATTERY_CUTOFF_REQUEST)) {
		VB2_DEBUG("Request to cut-off battery\n");
		vb2_nv_set(ctx, VB2_NV_BATTERY_CUTOFF_REQUEST, 0);

		/* May lose power immediately, so commit our update now. */
		VB2_TRY(vb2ex_commit_data(ctx));

		vb2ex_ec_battery_cutoff();
		return VB2_REQUEST_SHUTDOWN;
	}

	return VB2_SUCCESS;
}

static int is_valid_disk(VbDiskInfo *info, uint32_t disk_flags)
{
	return info->bytes_per_lba >= 512 &&
		(info->bytes_per_lba & (info->bytes_per_lba - 1)) == 0 &&
		info->lba_count >= 16 &&
		(info->flags & disk_flags & VB_DISK_FLAG_SELECT_MASK) &&
		((info->flags & VB_DISK_FLAG_SELECT_MASK) &
		 ((info->flags & VB_DISK_FLAG_SELECT_MASK) - 1)) == 0;
}

static vb2_error_t VbTryLoadKernelImpl(struct vb2_context *ctx,
				       uint32_t disk_flags, int minios,
				       uint32_t minios_flags)
{
	vb2_error_t rv = VB2_ERROR_LK_NO_DISK_FOUND;
	VbDiskInfo* disk_info = NULL;
	uint32_t disk_count = 0;
	uint32_t i;
	vb2_error_t new_rv;

	/* TODO: Should have been set by VbSelectAndLoadKernel. Remove when
	   this global is no longer needed. */
	VB2_ASSERT(kparams_ptr);

	kparams_ptr->disk_handle = NULL;

	/* Find disks */
	if (VB2_SUCCESS != VbExDiskGetInfo(&disk_info, &disk_count, disk_flags))
		disk_count = 0;

	/* Loop over disks */
	for (i = 0; i < disk_count; i++) {
		VB2_DEBUG("trying disk %d\n", (int)i);

		if (!is_valid_disk(&disk_info[i], disk_flags)) {
			VB2_DEBUG("  skipping: bytes_per_lba=%" PRIu64
				  " lba_count=%" PRIu64 " flags=%#x\n",
				  disk_info[i].bytes_per_lba,
				  disk_info[i].lba_count,
				  disk_info[i].flags);
			continue;
		}
		kparams_ptr->disk_handle = disk_info[i].handle;

		if (minios) {
			new_rv = LoadMiniOsKernel(ctx, kparams_ptr,
						  &disk_info[i], minios_flags);
			VB2_DEBUG("LoadMiniOsKernel() = %#x\n", new_rv);
		} else {
			new_rv = LoadKernel(ctx, kparams_ptr, &disk_info[i]);
			VB2_DEBUG("LoadKernel() = %#x\n", new_rv);
		}

		/* Stop now if we found a kernel. */
		if (VB2_SUCCESS == new_rv) {
			VbExDiskFreeInfo(disk_info, disk_info[i].handle);
			return VB2_SUCCESS;
		}

		/* Don't update error if we already have a more specific one. */
		if (VB2_ERROR_LK_INVALID_KERNEL_FOUND != rv)
			rv = new_rv;
	}

	/* If we drop out of the loop, we didn't find any usable kernel. */
	if (!(ctx->flags & VB2_CONTEXT_RECOVERY_MODE) &&
	    !(ctx->flags & VB2_CONTEXT_DEVELOPER_MODE)) {
		switch (rv) {
		case VB2_ERROR_LK_INVALID_KERNEL_FOUND:
			vb2api_fail(ctx, VB2_RECOVERY_RW_INVALID_OS, rv);
			break;
		case VB2_ERROR_LK_NO_KERNEL_FOUND:
			vb2api_fail(ctx, VB2_RECOVERY_RW_NO_KERNEL, rv);
			break;
		case VB2_ERROR_LK_NO_DISK_FOUND:
			vb2api_fail(ctx, VB2_RECOVERY_RW_NO_DISK, rv);
			break;
		default:
			vb2api_fail(ctx, VB2_RECOVERY_LK_UNSPECIFIED, rv);
			break;
		}
	}

	/* If we didn't find any good kernels, don't return a disk handle. */
	VbExDiskFreeInfo(disk_info, NULL);

	return rv;
}

test_mockable
vb2_error_t VbTryLoadKernel(struct vb2_context *ctx, uint32_t disk_flags)
{
	return VbTryLoadKernelImpl(ctx, disk_flags, 0, 0);
}

test_mockable
vb2_error_t VbTryLoadMiniOsKernel(struct vb2_context *ctx,
				  uint32_t minios_flags)
{
	return VbTryLoadKernelImpl(ctx, VB_DISK_FLAG_FIXED, 1, minios_flags);
}

vb2_error_t VbSelectAndLoadKernel(struct vb2_context *ctx,
				  VbSelectAndLoadKernelParams *kparams)
{
	struct vb2_shared_data *sd = vb2_get_sd(ctx);
	vb2_gbb_flags_t gbb_flags = vb2api_gbb_get_flags(ctx);

	/* TODO: Send this argument through subsequent function calls, rather
	   than relying on a global to pass it to VbTryLoadKernel. */
	kparams_ptr = kparams;

	/* Init nvstorage space. TODO(kitching): Remove once we add assertions
	   to vb2_nv_get and vb2_nv_set. */
	vb2_nv_init(ctx);

	VB2_TRY(vb2api_kernel_phase1(ctx));

	VB2_DEBUG("GBB flags are %#x\n", gbb_flags);

	/*
	 * Do EC and auxfw software sync unless we're in recovery mode. This
	 * has UI but it's just a single non-interactive WAIT screen.
	 */
	if (!(ctx->flags & VB2_CONTEXT_RECOVERY_MODE)) {
		VB2_TRY(vb2api_ec_sync(ctx));
		VB2_TRY(vb2api_auxfw_sync(ctx));
		VB2_TRY(handle_battery_cutoff(ctx));
	}

	/*
	 * If in the broken screen, save the recovery reason as subcode.
	 * Otherwise, clear any leftover recovery requests or subcodes.
	 */
	vb2_clear_recovery(ctx);

	/* Select boot path */
	switch (ctx->boot_mode) {
	case VB2_BOOT_MODE_MANUAL_RECOVERY:
	case VB2_BOOT_MODE_BROKEN_SCREEN:
		/* If we're in recovery mode just to do memory retraining, all
		   we need to do is reboot. */
		if (sd->recovery_reason == VB2_RECOVERY_TRAIN_AND_REBOOT) {
			VB2_DEBUG("Reboot after retraining in recovery\n");
			return VB2_REQUEST_REBOOT;
		}

		/*
		 * Need to commit nvdata changes immediately, since we will be
		 * entering either manual recovery UI or BROKEN screen shortly.
		 */
		vb2ex_commit_data(ctx);

		/*
		 * In EFS2, recovery mode can be entered even when battery is
		 * drained or damaged. EC-RO sets NO_BOOT flag in such case and
		 * uses PD power to boot AP.
		 *
		 * TODO: Inform user why recovery failed to start.
		 */
		if (ctx->flags & VB2_CONTEXT_NO_BOOT)
			VB2_DEBUG("NO_BOOT in RECOVERY mode\n");

		/* Recovery boot.  This has UI. */
		if (ctx->boot_mode == VB2_BOOT_MODE_MANUAL_RECOVERY)
			VB2_TRY(vb2ex_manual_recovery_ui(ctx));
		else
			VB2_TRY(vb2ex_broken_screen_ui(ctx));
		break;
	case VB2_BOOT_MODE_DIAGNOSTICS:
		/*
		 * Need to clear the request flag and commit nvdata changes
		 * immediately to avoid booting back into diagnostic tool when a
		 * forced system reset occurs.
		 */
		vb2_nv_set(ctx, VB2_NV_DIAG_REQUEST, 0);
		vb2ex_commit_data(ctx);

		/* Diagnostic boot.  This has UI. */
		VB2_TRY(vb2ex_diagnostic_ui(ctx));
		/*
		 * The diagnostic menu should either boot a rom, or
		 * return either of reboot or shutdown.
		 */
		return VB2_REQUEST_REBOOT;
	case VB2_BOOT_MODE_DEVELOPER:
		/* Developer boot.  This has UI. */
		VB2_TRY(vb2ex_developer_ui(ctx));
		break;
	case VB2_BOOT_MODE_NORMAL:
		/* Normal boot */
		VB2_TRY(vb2_normal_boot(ctx));
		break;
	default:
		return VB2_ERROR_ESCAPE_NO_BOOT;
	}

	/*
	 * Stop all cases returning SUCCESS against NO_BOOT flag except when
	 * GBB flag disables software sync.
	 */
	if (!(gbb_flags & VB2_GBB_FLAG_DISABLE_EC_SOFTWARE_SYNC)
	    && (ctx->flags & VB2_CONTEXT_EC_SYNC_SUPPORTED)
	    && (ctx->flags & VB2_CONTEXT_NO_BOOT)) {
		VB2_DEBUG("Blocking escape from NO_BOOT mode.\n");
		vb2api_fail(ctx, VB2_RECOVERY_ESCAPE_NO_BOOT, 0);
		return VB2_ERROR_ESCAPE_NO_BOOT;
	}

	return VB2_SUCCESS;
}
