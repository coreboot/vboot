/* Copyright (c) 2013 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Data structure and API definitions for a verified boot kernel image.
 * (Firmware Portion)
 */

#ifndef VBOOT_REFERENCE_VBOOT_KERNEL_H_
#define VBOOT_REFERENCE_VBOOT_KERNEL_H_

#include "cgptlib.h"
#include "gpt_misc.h"
#include "load_kernel_fw.h"
#include "vboot_api.h"

struct vb2_context;

/* Result codes for VbSharedDataKernelCall.check_result */
#define VBSD_LKC_CHECK_NOT_DONE            0
#define VBSD_LKC_CHECK_DEV_SWITCH_MISMATCH 1
#define VBSD_LKC_CHECK_GPT_READ_ERROR      2
#define VBSD_LKC_CHECK_GPT_PARSE_ERROR     3
#define VBSD_LKC_CHECK_GOOD_PARTITION      4
#define VBSD_LKC_CHECK_INVALID_PARTITIONS  5
#define VBSD_LKC_CHECK_NO_PARTITIONS       6

/* Information about a single call to LoadKernel() */
typedef struct VbSharedDataKernelCall {
	/* Bottom 32 bits of flags passed in LoadKernelParams.boot_flags */
	uint32_t boot_flags;
	/* Debug flags; see VBSD_LK_FLAG_* */
	uint32_t flags;
	/* Number of sectors on drive */
	uint64_t sector_count;
	/* Sector size in bytes */
	uint32_t sector_size;
	/* Check result; see VBSD_LKC_CHECK_* */
	uint8_t check_result;
	/* Test error number, if non-zero */
	uint8_t test_error_num;
	/* Return code from LoadKernel() */
	uint8_t return_code;
	/* Number of kernel partitions found */
	uint8_t kernel_parts_found;
	/* Reserved for padding */
	uint8_t reserved0[199];
} VbSharedDataKernelCall;

/**
 * Attempt loading a kernel from the specified type(s) of disks.
 *
 * If successful, sets lkp.disk_handle to the disk for the kernel and returns
 * VB2_SUCCESS.
 *
 * @param ctx			Vboot context
 * @param get_info_flags	Flags to pass to VbExDiskGetInfo()
 * @return VB2_SUCCESS or the most specific VB2_ERROR_LK error.
 */
vb2_error_t VbTryLoadKernel(struct vb2_context *ctx, uint32_t get_info_flags);

#endif  /* VBOOT_REFERENCE_VBOOT_KERNEL_H_ */
